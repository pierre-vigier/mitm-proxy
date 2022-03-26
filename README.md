# mitm-proxy

Test with tls proxy in Golang

For local test, air is used to auto reload the app

Use [air](https://github.com/cosmtrek/air) for autoreload and running of the local server:

```
air
```

Usefull command list for certificates:
https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs

Generate a self signed certificate for terminating TLS

```
openssl req -newkey rsa:2048 -nodes -keyout private.key -x509 -days 365 -out certificate.crt
```