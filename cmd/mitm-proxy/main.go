package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/pierre-vigier/mitm-proxy/internal/proxy"
)

func main() {
	log.Println("Start")
	p, err := proxy.New()
	if err != nil {
		panic(err)
	}
	server := &http.Server{
		Addr:         ":8080",
		Handler:      p,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Fatal(server.ListenAndServe())
}
