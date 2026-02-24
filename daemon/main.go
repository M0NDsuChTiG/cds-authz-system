// daemon/main.go
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

// TrustEntry - структура для trusted digest
type TrustEntry struct {
	Image  string    `json:"image"`
	Digest string    `json:"digest"`
	TTL    time.Time `json:"ttl"`
}

// TrustDB - in-memory store (замени на SQLite/BoltDB позже)
var trustDB = make(map[string]TrustEntry) // key: digest

func main() {
	socketPath := "/run/cds-daemon.sock"
	os.Remove(socketPath) // cleanup if exists

	r := mux.NewRouter()
	r.HandleFunc("/trust/add", addTrustHandler).Methods("POST") // для CLI/API
	r.HandleFunc("/trust/check", checkTrustHandler).Methods("POST") // для plugin

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		panic(fmt.Sprintf("Error listening on socket: %v", err))
	}
	defer l.Close()
	os.Chmod(socketPath, 0660) // secure permissions

	fmt.Println("cds-daemon started on", socketPath)
	go http.Serve(l, r)

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("Shutting down cds-daemon...")
}

// addTrustHandler - добавление trust (для CLI)
func addTrustHandler(w http.ResponseWriter, r *http.Request) {
	var entry TrustEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// TODO: validate digest, cosign verify
	trustDB[entry.Digest] = entry
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "added"})
}

// checkTrustHandler - проверка для plugin (fail-closed if not found or expired)
func checkTrustHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entry, exists := trustDB[req.Digest]
	if !exists || entry.TTL.Before(time.Now()) {
		http.Error(w, "DENY: not trusted or expired", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ALLOW"})
}
