package proxy

import (
	"bufio"
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
	"log"
	"math/big"
	"net/http"
	"net/url"
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

type Proxy struct {
	caCert *tls.Certificate
	cax509 *x509.Certificate
}

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
		// TODO : Timeout management
		transport := &http.Transport{
			// Deacticating HTTP2 when calling upstream
			TLSClientConfig: &tls.Config{},
		}
		resp, err := transport.RoundTrip(clientRequest)

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

func (p *Proxy) generateHostCert(host string) *tls.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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
