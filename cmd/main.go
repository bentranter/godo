package main

import (
	"net/http"
	"os"

	"github.com/digitalocean/godo"
)

func main() {
	c, err := godo.NewOAuth2(&godo.OAuth2Config{
		ClientID:     os.Getenv("DIGITALOCEAN_APP_ID"),
		ClientSecret: os.Getenv("DIGITALOCEAN_SECRET"),
		RedirectURL:  "http://localhost:3000/auth/digitalocean/callback",
	})
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<h1>OAuth2 Test</h1><a href="/auth/digitalocean/authorize">Authenticate with DigitalOcean</a>`))
	})

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		account, _, err := c.Account.Get(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`<p>Connected successfully as` + account.Email + `</p><a href="/">Home</a>`))
	})

	http.HandleFunc("/auth/digitalocean/authorize", c.OAuth2.Authorize)
	http.Handle("/auth/digitalocean/callback", c.OAuth2.Callback("/auth"))

	http.ListenAndServe(":3000", nil)
}
