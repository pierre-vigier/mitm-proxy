package proxy

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func New() (*Proxy, error) {
	// load our certificates
	cert, err := tls.LoadX509KeyPair("certificate.crt", "private.key")
	if err != nil {
		return nil, fmt.Errorf("Could not load key pair: %s", err.Error())
	}
	ca, err := x509.ParseCertificate(cert.Certificate[0])
	// todo manage error
	if err != nil {
		return nil, fmt.Errorf("Could not parse certificate: %s", err.Error())
	}
	return &Proxy{
		caCert: &cert,
		cax509: ca,
	}, nil
}

type route struct {
	host                 *string
	scheme               *string
	pathString           *string
	pathRegexp           *regexp.Regexp
	methods              []string
	handler              ProxyHandler
	requestInterceptors  []ProxyRequestInterceptor
	responseInterceptors []ProxyResponseInterceptor
}

func (r *route) Host(host string) *route {
	r.host = &host
	return r
}
func (r *route) Scheme(scheme string) *route {
	r.scheme = &scheme
	return r
}
func (r *route) PathString(path string) *route {
	r.pathString = &path
	return r
}
func (r *route) PathRegexp(path string) *route {
	r.pathRegexp = regexp.MustCompile(path)
	return r
}
func (r *route) Methods(methods ...string) *route {
	r.methods = append(r.methods, methods...)
	return r
}
func (r *route) Handler(h ProxyHandler) *route {
	r.handler = h
	return r
}
func (r *route) AddRequestInterceptor(m ProxyRequestInterceptor) *route {
	r.requestInterceptors = append(r.requestInterceptors, m)
	return r
}
func (r *route) AddResponseInterceptor(m ProxyResponseInterceptor) *route {
	r.responseInterceptors = append(r.responseInterceptors, m)
	return r
}
func (r *route) isMatching(req *http.Request) bool {
	if r.host != nil && *r.host != req.URL.Hostname() {
		return false
	}
	if r.methods != nil {
		found := false
		for _, m := range r.methods {
			if m == req.Method {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if r.scheme != nil {
		if *r.scheme != req.URL.Scheme {
			return false
		}
	}
	if r.pathString != nil {
		if *r.pathString != req.URL.Path {
			return false
		}
	}
	if r.pathRegexp != nil {
		if !r.pathRegexp.MatchString(req.URL.Path) {
			return false
		}
	}
	return true
}

type Proxy struct {
	caCert               *tls.Certificate
	cax509               *x509.Certificate
	routes               []*route
	defaultHandler       ProxyHandler
	requestInterceptors  []ProxyRequestInterceptor
	responseInterceptors []ProxyResponseInterceptor
}

func (p *Proxy) CatchAll(h ProxyHandler) *Proxy {
	p.defaultHandler = h
	return p
}

func (p *Proxy) AddRequestInterceptor(m ProxyRequestInterceptor) *Proxy {
	p.requestInterceptors = append(p.requestInterceptors, m)
	return p
}

func (p *Proxy) AddResponseInterceptor(m ProxyResponseInterceptor) *Proxy {
	p.responseInterceptors = append(p.responseInterceptors, m)
	return p
}

func (p *Proxy) NewRoute() *route {
	r := &route{}
	p.routes = append(p.routes, r)
	return r
}

type ProxyHandler func(*http.Request) (*http.Response, error)
type ProxyRequestInterceptor func(*http.Request) (*http.Request, error)
type ProxyResponseInterceptor func(*http.Response) (*http.Response, error)

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Method: %s", r.Method)
	if r.Method == http.MethodConnect {
		p.HandleTLS(w, r)
		return
	}
	// We should probably not use default transport there
	// Missing timeout management
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		log.Printf("Can't proxy : %s", err.Error())
		http.Error(w, "Can't proxy", http.StatusServiceUnavailable)
		return
	}
	resp.Write(w)
}

func (p *Proxy) HandleTLS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("could not hijack connection")
		http.Error(w, "Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	clientConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	defer clientConn.Close()

	// generate certificate for the host, signed by ourselves
	// in other words: Man in the middle "attack"
	fragments := strings.Split(r.Host, ":")
	host := fragments[0]

	hostCert := p.generateHostCert(host)

	tlsConfig := tls.Config{Certificates: []tls.Certificate{*hostCert}}
	tlsNewClientCon := tls.Server(clientConn, &tlsConfig)
	defer tlsNewClientCon.Close()
	err = tlsNewClientCon.Handshake()
	if err != nil {
		log.Printf("TLS handshake with client failed: %s", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	reader := bufio.NewReader(tlsNewClientCon)
	for {
		//until client stop, read and forward request
		clientRequest, err := http.ReadRequest(reader)
		if err != nil && err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Could not read request: %s", err.Error())
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if r.URL.String()[:8] != "https://" {
			clientRequest.URL, err = url.Parse("https://" + r.Host + clientRequest.URL.String())
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		resp, err := p.HandleRequest(clientRequest)

		if err != nil {
			log.Printf("Can't proxy : %s", err.Error())
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if err = resp.Write(tlsNewClientCon); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			log.Printf("error sending back response: %s", err.Error())
			return
		}
	}
}

func (p *Proxy) HandleRequest(req *http.Request) (*http.Response, error) {
	//common request interceptors
	var err error
	var resp *http.Response
	for _, i := range p.requestInterceptors {
		req, err = i(req)
		if err != nil {
			return resp, err
		}
	}

	// Stop at the first matching route
	matched := false
	for _, route := range p.routes {
		if route.isMatching(req) {
			matched = true
			for _, i := range route.requestInterceptors {
				req, err = i(req)
				if err != nil {
					return resp, err
				}
			}

			if route.handler != nil {
				resp, err = route.handler(req)
			} else {
				resp, err = ForwardHandler(req)
			}
			if err != nil {
				return resp, err
			}
			for _, i := range route.responseInterceptors {
				resp, err = i(resp)
				if err != nil {
					return resp, err
				}
			}
		}
	}
	// No Route found
	if !matched {
		if p.defaultHandler != nil {
			resp, err = p.defaultHandler(req)
		} else {
			resp, err = DenyHandler(req)
		}
	}
	// common response interceptor
	for _, i := range p.responseInterceptors {
		resp, err = i(resp)
		if err != nil {
			return resp, err
		}
	}
	return resp, err
}

func ForwardHandler(req *http.Request) (*http.Response, error) {
	// TODO : Timeout management
	transport := &http.Transport{
		// Deacticating HTTP2 when calling upstream
		TLSClientConfig: &tls.Config{},
	}
	// if there's middleware that's the place
	resp, err := transport.RoundTrip(req)
	return resp, err
}

func DenyHandler(req *http.Request) (*http.Response, error) {
	return newResponse(req, "text/plain", 401, "Blocked by proxy"), nil
}

func newResponse(r *http.Request, contentType string, status int, body string) *http.Response {
	resp := &http.Response{}
	resp.Request = r
	resp.TransferEncoding = r.TransferEncoding
	resp.Header = make(http.Header)
	resp.Header.Add("Content-Type", contentType)
	resp.StatusCode = status
	resp.Status = http.StatusText(status)
	resp.Proto = r.Proto
	resp.ProtoMajor = r.ProtoMajor
	resp.ProtoMinor = r.ProtoMinor
	buf := bytes.NewBufferString(body)
	resp.ContentLength = int64(buf.Len())
	resp.Body = ioutil.NopCloser(buf)
	return resp
}

func (p *Proxy) generateHostCert(host string) *tls.Certificate {
	serial, _ := rand.Int(rand.Reader, big.NewInt(2000000000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"PVI"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24), // one day, as, why not
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	//IP or host? managing only host for now
	template.DNSNames = append(template.DNSNames, host)
	template.Subject.CommonName = host

	var pk crypto.Signer
	var err error
	switch p.caCert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		pk, err = rsa.GenerateKey(rand.Reader, 2048)
	case *ecdsa.PrivateKey:
		pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		err = fmt.Errorf("unsupported key type %T", p.caCert.PrivateKey)
	}
	if err != nil {
		return nil
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, p.cax509, pk.Public(), p.caCert.PrivateKey)
	if err != nil {
		return nil
	}

	return &tls.Certificate{
		Certificate: [][]byte{cert, p.caCert.Certificate[0]},
		PrivateKey:  pk,
	}
}
