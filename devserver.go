package main

import (
	"log"
	"net/http"
	"os"

	profiles "portguard/api/profiles"
	scan "portguard/api/scan"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profiles", profiles.Handler)
	mux.HandleFunc("/api/scan", scan.Handler)
	mux.Handle("/", http.FileServer(http.Dir("public")))
	port := os.Getenv("PORT")
	if port == "" { port = "8080" }
	log.Printf("PortGuard local server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
