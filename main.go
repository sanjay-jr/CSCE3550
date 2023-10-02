package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func main() {
	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)

	port := 8080
	fmt.Printf("Server listening on port %d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Found", http.StatusMethodNotAllowed)
		return
	}

	keys := []JWK{
		{
			Kty: "RSA",
			Kid: "my-key-id",
			Use: "sig",
			N:   "public_key_here",
			E:   "AQAB",
		},
	}

	response := JWKSResponse{Keys: keys}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Found", http.StatusMethodNotAllowed)
		return
	}

	response := "JWT_TOKEN_HERE"
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(response))
}
