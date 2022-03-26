package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
)

func main() {
	log.Println("Start")
	server := &http.Server{
		Addr:         ":3777",
		Handler:      http.HandlerFunc(Handler),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Fatal(server.ListenAndServe())
}

func Handler(w http.ResponseWriter, r *http.Request) {
	// We should probably not use default transport there
	// Missing timeout management
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		log.Printf("Can't proxy : %s", err.Error())
		http.Error(w, "Can't proxy", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
