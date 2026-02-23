package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	socketPath = "/run/cds.sock"
	dataDir    = "/var/lib/cds"
	dbPath     = "/var/lib/cds/trust.db"
	trustTTL   = 24 * time.Hour
)

type TrustEntry struct {
	Digest    string `json:"digest"`
	Status    string `json:"status"` // VERIFIED | FAILED
	Reason    string `json:"reason"`
	UpdatedAt int64  `json:"updated_at"`
}

type Server struct {
	mu    sync.RWMutex
	cache map[string]TrustEntry
}

func newServer() *Server {
	s := &Server{
		cache: make(map[string]TrustEntry),
	}
	s.loadFromDisk()
	return s
}

func (s *Server) loadFromDisk() {
	file, err := os.Open(dbPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Error opening database %s: %v", dbPath, err)
		}
		return
	}
	defer file.Close()

	log.Printf("Loading trust entries from %s", dbPath)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry TrustEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			s.cache[entry.Digest] = entry
		}
	}
	log.Printf("Loaded %d entries into memory cache.", len(s.cache))
}

func (s *Server) persist(entry TrustEntry) {
	// Ensure data directory exists and has correct permissions
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Printf("persist error: could not create data directory %s: %v", dataDir, err)
		return
	}

	f, err := os.OpenFile(dbPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Println("persist error:", err)
		return
	}
	defer f.Close()
	
	b, err := json.Marshal(entry)
	if err != nil {
		log.Printf("persist error: could not marshal entry: %v", err)
		return
	}

	if _, err := f.Write(append(b, '\n')); err != nil {
		log.Printf("persist error: could not write to db: %v", err)
	}
}

func (s *Server) checkHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp := map[string]interface{}{
		"decision": "DENY",
		"reason":   "unknown",
		"ts":       time.Now().Unix(),
	}

	s.mu.RLock()
	entry, ok := s.cache[req.Digest]
	s.mu.RUnlock()

	if !ok {
		json.NewEncoder(w).Encode(resp)
		return
	}

	if entry.Status != "VERIFIED" {
		resp["reason"] = entry.Reason
		json.NewEncoder(w).Encode(resp)
		return
	}

	if time.Since(time.Unix(entry.UpdatedAt, 0)) > trustTTL {
		resp["reason"] = "stale"
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp["decision"] = "ALLOW"
	resp["reason"] = "verified"
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) updateHandler(w http.ResponseWriter, r *http.Request) {
	var entry TrustEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if entry.UpdatedAt == 0 {
		entry.UpdatedAt = time.Now().Unix()
	}

	s.mu.Lock()
	s.cache[entry.Digest] = entry
	s.mu.Unlock()

	s.persist(entry)
	log.Printf("Updated/persisted trust for digest: %s, Status: %s", entry.Digest, entry.Status)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"stored": true})
}

func main() {
	// Systemd socket activation will provide the socket, so the daemon
	// doesn't need to create it. However, for standalone execution,
	// we keep the manual socket creation logic.
	
	var l net.Listener
	var err error

	// This check allows the daemon to be run either by systemd or manually.
	// If systemd provides the socket, it sets LISTEN_FDS > 0.
	if os.Getenv("LISTEN_FDS") != "" {
		log.Println("Detected systemd socket activation.")
		// The socket is passed as file descriptor 3.
		f := os.NewFile(3, "socket")
		l, err = net.FileListener(f)
		if err != nil {
			log.Fatalf("net.FileListener error: %v", err)
		}
	} else {
		log.Println("Running in standalone mode. Creating socket manually.")
		os.MkdirAll(dataDir, 0700)
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			log.Fatalf("Failed to remove old socket: %v", err)
		}

		l, err = net.Listen("unix", socketPath)
		if err != nil {
			log.Fatal(err)
		}
		// In standalone mode, we must set permissions ourselves.
		// Systemd handles this when using socket units.
		if err := os.Chmod(socketPath, 0600); err != nil {
			log.Fatalf("Failed to set socket permissions: %v", err)
		}
	}
	
	server := newServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/check", server.checkHandler)
	mux.HandleFunc("/v1/update", server.updateHandler)

	log.Println("CDS daemon started, listening for requests...")
	if err := http.Serve(l, mux); err != nil {
		log.Fatalf("http.Serve error: %v", err)
	}
}
