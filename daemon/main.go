package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	bolt "go.etcd.io/bbolt"
)

// API v1.1 Models
type TrustEntry struct {
	Target            string    `json:"target"`
	Digest            string    `json:"digest"`
	RequireSignature  bool      `json:"require_signature"`
	PublicKeyID       string    `json:"public_key_id,omitempty"`
	SignatureVerified bool      `json:"signature_verified"`
	VerifiedAt        time.Time `json:"verified_at,omitempty"`
	AddedAt           time.Time `json:"added_at"`
}

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // "CHECK", "ADD", "REMOVE", "VERIFY"
	Image     string    `json:"image"`
	Digest    string    `json:"digest"`
	Decision  string    `json:"decision"` // "ALLOW", "DENY"
	Reason    string    `json:"reason,omitempty"`
}

type KeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func (ks *KeyStore) Get(id string) ([]byte, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	v, ok := ks.keys[id]
	return v, ok
}

var (
	db            *bolt.DB
	trustBucket   = []byte("trust")
	auditBucket   = []byte("audit_events")
	dbPath        = "/var/lib/cds/trust.db"
	socketPath    = "/run/cds/cds.sock"
	dockerSocket  = "/var/run/docker.sock"
	keyStoreDir   = "/var/lib/cds/keys"
	ks            *KeyStore
)

func main() {
	var err error
	db, err = bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		panic(fmt.Sprintf("Failed to open BoltDB: %v", err))
	}
	defer db.Close()

	ks = &KeyStore{keys: make(map[string][]byte)}
	loadKeys(ks)

	err = db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists(trustBucket)
		tx.CreateBucketIfNotExists(auditBucket)
		return nil
	})
	if err != nil {
		panic(err)
	}

	os.Remove(socketPath)
	r := mux.NewRouter()
	v1 := r.PathPrefix("/v1").Subrouter()
	v1.HandleFunc("/health", healthHandler).Methods("GET")
	v1.HandleFunc("/trust", listTrustHandler).Methods("GET")
	v1.HandleFunc("/trust/add", addTrustHandler).Methods("POST")
	v1.HandleFunc("/trust/remove", removeTrustHandler).Methods("POST")
	v1.HandleFunc("/trust/check", checkTrustHandler).Methods("POST")
	v1.HandleFunc("/audit", listAuditHandler).Methods("GET")
	v1.HandleFunc("/keys", listKeysHandler).Methods("GET")

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	os.Chmod(socketPath, 0660)

	fmt.Printf("cds-daemon v6.6 (Signature Enforcement) started. %d keys loaded.\n", len(ks.keys))
	go http.Serve(l, r)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

func loadKeys(ks *KeyStore) {
	files, err := ioutil.ReadDir(keyStoreDir)
	if err != nil {
		return
	}
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".pub") {
			content, err := ioutil.ReadFile(filepath.Join(keyStoreDir, f.Name()))
			if err == nil {
				id := strings.TrimSuffix(f.Name(), ".pub")
				ks.keys[id] = content
				fmt.Printf("KeyStore: Loaded public key '%s'\n", id)
			}
		}
	}
}

// verifySignature - calls cosign to verify image@digest
func verifySignature(target, digest, keyID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyPath := filepath.Join(keyStoreDir, keyID+".pub")
	imageRef := fmt.Sprintf("%s@%s", strings.Split(target, ":")[0], digest)

	cmd := exec.CommandContext(ctx, "cosign", "verify", "--key", keyPath, imageRef)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("Verification timeout (504)")
	}

	if err != nil {
		return fmt.Errorf("Signature verification failed: %v (Output: %s)", err, string(output))
	}
	return nil
}

func addTrustHandler(w http.ResponseWriter, r *http.Request) {
	var entry TrustEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if entry.RequireSignature {
		if _, ok := ks.Get(entry.PublicKeyID); !ok {
			http.Error(w, "PublicKeyID not found", http.StatusBadRequest)
			return
		}
		// Phase D3: Atomic verification
		fmt.Printf("Daemon: Verifying signature for %s under key %s...\n", entry.Target, entry.PublicKeyID)
		if err := verifySignature(entry.Target, entry.Digest, entry.PublicKeyID); err != nil {
			logAudit("VERIFY", entry.Target, entry.Digest, "DENY", err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		entry.SignatureVerified = true
		entry.VerifiedAt = time.Now()
		logAudit("VERIFY", entry.Target, entry.Digest, "ALLOW", "cosign_success")
	}

	entry.AddedAt = time.Now()
	value, _ := json.Marshal(entry)
	db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(trustBucket).Put([]byte(entry.Digest), value)
	})
	logAudit("ADD", entry.Target, entry.Digest, "ALLOW", "manual_add")
	w.WriteHeader(http.StatusCreated)
}

// Other handlers (unchanged from v6.5 but included for completeness)
func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{"healthy": true, "keys": len(ks.keys)})
}
func listKeysHandler(w http.ResponseWriter, r *http.Request) {
	var ids []string
	ks.mu.RLock()
	for id := range ks.keys { ids = append(ids, id) }
	ks.mu.RUnlock()
	json.NewEncoder(w).Encode(ids)
}
func listTrustHandler(w http.ResponseWriter, r *http.Request) {
	var entries []TrustEntry
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(trustBucket)
		return b.ForEach(func(k, v []byte) error {
			var entry TrustEntry
			json.Unmarshal(v, &entry)
			entries = append(entries, entry)
			return nil
		})
	})
	json.NewEncoder(w).Encode(entries)
}
func listAuditHandler(w http.ResponseWriter, r *http.Request) {
	var entries []AuditEntry
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditBucket)
		return b.ForEach(func(k, v []byte) error {
			var entry AuditEntry
			json.Unmarshal(v, &entry)
			entries = append(entries, entry)
			return nil
		})
	})
	json.NewEncoder(w).Encode(entries)
}
func removeTrustHandler(w http.ResponseWriter, r *http.Request) {
	var req struct { Target string `json:"target"` }
	json.NewDecoder(r.Body).Decode(&req)
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(trustBucket)
		return b.ForEach(func(k, v []byte) error {
			var entry TrustEntry
			json.Unmarshal(v, &entry)
			if entry.Target == req.Target { return b.Delete(k) }
			return nil
		})
	})
	w.WriteHeader(http.StatusOK)
}
func resolveDigest(image string) (string, error) {
	httpClient := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return net.Dial("unix", dockerSocket) }}}
	resp, err := httpClient.Get(fmt.Sprintf("http://localhost/images/%s/json", image))
	if err != nil { return "", err }
	defer resp.Body.Close()
	var info struct { RepoDigests []string `json:"RepoDigests"`; Id string `json:"Id"` }
	json.NewDecoder(resp.Body).Decode(&info)
	digest := info.Id
	if len(info.RepoDigests) > 0 {
		parts := strings.Split(info.RepoDigests[0], "@")
		if len(parts) == 2 { digest = parts[1] }
	}
	if !strings.HasPrefix(digest, "sha256:") { digest = "sha256:" + digest }
	return digest, nil
}
func checkTrustHandler(w http.ResponseWriter, r *http.Request) {
	var req struct { Image string `json:"Image"` }
	json.NewDecoder(r.Body).Decode(&req)
	digest, err := resolveDigest(req.Image)
	if err != nil { 
		logAudit("CHECK", req.Image, "", "DENY", "resolver_error")
		json.NewEncoder(w).Encode(map[string]interface{}{"Allow": false, "Reason": "resolver_error"})
		return
	}
	var exists bool
	db.View(func(tx *bolt.Tx) error {
		exists = (tx.Bucket(trustBucket).Get([]byte(digest)) != nil)
		return nil
	})
	decision := "DENY"
	if exists { decision = "ALLOW" }
	logAudit("CHECK", req.Image, digest, decision, "")
	json.NewEncoder(w).Encode(map[string]interface{}{"Allow": exists, "Digest": digest})
}
func logAudit(action, image, digest, decision, reason string) {
	entry := AuditEntry{Timestamp: time.Now(), Action: action, Image: image, Digest: digest, Decision: decision, Reason: reason}
	value, _ := json.Marshal(entry)
	db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(auditBucket).Put([]byte(fmt.Sprintf("%d", time.Now().UnixNano())), value)
	})
}
