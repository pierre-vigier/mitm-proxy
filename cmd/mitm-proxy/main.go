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
	p.CatchAll(proxy.DenyHandler).AddRequestInterceptor(func(req *http.Request) (*http.Request, error) {
		log.Printf("Common request interceptor, method: %s", req.Method)
		return req, nil
	}).AddResponseInterceptor(func(resp *http.Response) (*http.Response, error) {
		log.Printf("Common response interceptor")
		return resp, nil
	})
	p.NewRoute().Methods("POST").Handler(proxy.ForwardHandler).AddRequestInterceptor(func(req *http.Request) (*http.Request, error) {
		log.Printf("Route request interceptor, method: %s", req.Method)
		return req, nil
	}).AddResponseInterceptor(func(resp *http.Response) (*http.Response, error) {
		log.Printf("Route response interceptor")
		return resp, nil
	})

	server := &http.Server{
		Addr:         ":3777",
		Handler:      p,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Fatal(server.ListenAndServe())
}
