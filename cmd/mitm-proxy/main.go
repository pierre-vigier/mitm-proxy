package main

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

func main() {
	log.Println("Start")
	server := &http.Server{
		Addr:         ":8080",
		Handler:      http.HandlerFunc(Handler),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Fatal(server.ListenAndServe())
}

func HandleTLS(w http.ResponseWriter, r *http.Request) {
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

	// load our certificates
	cert, err := tls.LoadX509KeyPair("certificate.crt", "private.key")
	if err != nil {
		log.Printf("Could not load certificate: %s", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	hostCert := generateHostCert(host, cert)
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
		}
		log.Println(clientRequest.URL.String())
		if r.URL.String()[:8] != "https://" {
			clientRequest.URL, err = url.Parse("https://" + r.Host + clientRequest.URL.String())
			log.Println("Changing URL")
		}
		if err != nil {
			return
		}
		// TODO : Timeout management
		transport := &http.Transport{
			// Deacticating HTTP2 when calling upstream
			TLSClientConfig: &tls.Config{},
		}
		resp, err := transport.RoundTrip(clientRequest)

		if err != nil {
			log.Printf("Can't proxy : %s", err.Error())
			return
		}
		if err = resp.Write(tlsNewClientCon); err != nil {
			log.Printf("error sending back response: %s", err.Error())
		}
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func generateHostCert(host string, certAuthority tls.Certificate) *tls.Certificate {
	ca, err := x509.ParseCertificate(certAuthority.Certificate[0])
	// todo manage error
	if err != nil {
		return nil
	}
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

	//IP or host?
	template.DNSNames = append(template.DNSNames, host)
	template.Subject.CommonName = host

	var pk crypto.Signer
	switch certAuthority.PrivateKey.(type) {
	case *rsa.PrivateKey:
		pk, err = rsa.GenerateKey(rand.Reader, 2048)
	case *ecdsa.PrivateKey:
		pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		err = fmt.Errorf("unsupported key type %T", certAuthority.PrivateKey)
	}
	if err != nil {
		return nil
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, ca, pk.Public(), certAuthority.PrivateKey)
	if err != nil {
		return nil
	}

	return &tls.Certificate{
		Certificate: [][]byte{cert, certAuthority.Certificate[0]},
		PrivateKey:  pk,
	}
}

func Handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Method: %s", r.Method)
	if r.Method == http.MethodConnect {
		HandleTLS(w, r)
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
