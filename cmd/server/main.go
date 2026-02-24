package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type application struct{}

func (app *application) healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status": "Sanctum is alive",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	log.Printf("%v %v %v", r.Method, r.RequestURI, http.StatusOK)
}

func main() {
	app := &application{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", app.healthcheckHandler)

	log.Println("Starting Sanctum vault on :8080")

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatalf("Server breached or failed to start: %v", err)
	}
}
