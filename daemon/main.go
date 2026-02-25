package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	"log/syslog"

	"github.com/gorilla/mux"
	bolt "go.etcd.io/bbolt"
)

// Policy Config
type Policy struct {
	RevalidateOnRevoke   bool `json:"revalidate_on_key_revoke"`
	RevalidateOnRotation bool `json:"revalidate_on_key_rotation"`
}

var globalPolicy = Policy{
	RevalidateOnRevoke:   true,
	RevalidateOnRotation: false,
}

// API Models
type KeyRecord struct {
	ID          string    `json:"id"`
	Raw         []byte    `json:"raw"`
	Fingerprint string    `json:"fingerprint"`
	Version     int       `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	Revoked     bool      `json:"revoked"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
}

type TrustEntry struct {
	Target            string    `json:"target"`
	Digest            string    `json:"digest"`
	RequireSignature  bool      `json:"require_signature"`
	PublicKeyID       string    `json:"public_key_id,omitempty"`
	KeyVersion        int       `json:"key_version,omitempty"`
	SignatureVerified bool      `json:"signature_verified"`
	VerifiedAt        time.Time `json:"verified_at,omitempty"`
	AddedAt           time.Time `json:"added_at"`
}

type AuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Image       string    `json:"image,omitempty"`
	Digest      string    `json:"digest,omitempty"`
	KeyID       string    `json:"key_id,omitempty"`
	KeyVersion  int       `json:"key_version,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Decision    string    `json:"decision"`
	Reason      string    `json:"reason,omitempty"`
}

type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]KeyRecord
}

func (ks *KeyStore) Get(id string) (KeyRecord, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	v, ok := ks.keys[id]
	return v, ok
}

func (ks *KeyStore) Set(kr KeyRecord) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[kr.ID] = kr
}

var (
	db            *bolt.DB
	trustBucket   = []byte("trust_records")
	keysBucket    = []byte("keys")
	auditBucket   = []byte("audit_events")
	dbPath        = "/var/lib/cds/trust.db"
	socketPath    = "/run/cds/cds.sock"
	dockerSocket  = "/var/run/docker.sock"
	ks            *KeyStore
	auditBackends = []string{"bolt", "syslog"}
)

func main() {
	var err error
	db, err = bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists(trustBucket)
		tx.CreateBucketIfNotExists(keysBucket)
		tx.CreateBucketIfNotExists(auditBucket)
		return nil
	})
	if err != nil {
		panic(err)
	}

	ks = &KeyStore{keys: make(map[string]KeyRecord)}
	loadKeysFromDB()

	os.Remove(socketPath)
	r := mux.NewRouter()
	v1 := r.PathPrefix("/v1").Subrouter()
	
	v1.HandleFunc("/keys", listKeysHandler).Methods("GET")
	v1.HandleFunc("/keys/import", importKeyHandler).Methods("POST")
	v1.HandleFunc("/keys/revoke", revokeKeyHandler).Methods("POST")
	v1.HandleFunc("/trust", listTrustHandler).Methods("GET")
	v1.HandleFunc("/trust/add", addTrustHandler).Methods("POST")
	v1.HandleFunc("/trust/remove", removeTrustHandler).Methods("POST")
	v1.HandleFunc("/trust/check", checkTrustHandler).Methods("POST")
	v1.HandleFunc("/audit", listAuditHandler).Methods("GET")
	v1.HandleFunc("/audit/export", exportAuditHandler).Methods("GET")
	v1.HandleFunc("/health", healthHandler).Methods("GET")

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	os.Chmod(socketPath, 0660)

	fmt.Printf("cds-daemon v0.6.0 (Managed Trust Authority) started.\n")
	go http.Serve(l, r)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

func loadKeysFromDB() {
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(keysBucket)
		if b == nil { return nil }
		return b.ForEach(func(k, v []byte) error {
			var kr KeyRecord
			if err := json.Unmarshal(v, &kr); err == nil {
				ks.keys[kr.ID] = kr
			}
			return nil
		})
	})
}

func fingerprintPEM(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil { return "", errors.New("invalid PEM") }
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:]), nil
}

func emitAuditSyslog(ev AuditEntry) {
	s, _ := json.Marshal(ev)
	w, err := syslog.Dial("", "", syslog.LOG_INFO|syslog.LOG_LOCAL0, "cds")
	if err != nil { return }
	defer w.Close()
	w.Info(string(s))
}

func logAudit(entry AuditEntry) {
	entry.Timestamp = time.Now()
	value, _ := json.Marshal(entry)
	
	// Backend 1: BoltDB
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditBucket)
		key := fmt.Sprintf("%d", time.Now().UnixNano())
		return b.Put([]byte(key), value)
	})

	// Backend 2: Syslog
	for _, b := range auditBackends {
		if b == "syslog" {
			emitAuditSyslog(entry)
		}
	}
}

func exportAuditHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("["))

	first := true
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditBucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if !first { w.Write([]byte(",")) }
			first = false
			w.Write(v)
			if f, ok := w.(http.Flusher); ok { f.Flush() }
		}
		return nil
	})
	w.Write([]byte("]"))
}

func verifySignature(target, digest, keyID string) (int, error) {
	kr, ok := ks.Get(keyID)
	if !ok || kr.Revoked { return 0, errors.New("invalid or revoked key") }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tempKey := filepath.Join("/tmp", "cds-verify-"+keyID+".pub")
	os.WriteFile(tempKey, kr.Raw, 0600); defer os.Remove(tempKey)
	imageRef := fmt.Sprintf("%s@%s", strings.Split(target, ":")[0], digest)
	cmd := exec.CommandContext(ctx, "cosign", "verify", "--key", tempKey, "--offline", "--rekor-url", "disabled", imageRef)
	cmd.Env = append(os.Environ(), "COSIGN_EXPERIMENTAL=0", "SIGSTORE_NO_CACHE=1", "TUF_ROOT=", "HOME=/tmp")
	cmd.Dir = "/tmp"
	if err := cmd.Run(); err != nil { return 0, fmt.Errorf("verification failed: %v", err) }
	return kr.Version, nil
}

func checkTrustHandler(w http.ResponseWriter, r *http.Request) {
	var req struct { Image string `json:"Image"` }
	json.NewDecoder(r.Body).Decode(&req)
	digest, err := resolveDigest(req.Image)
	if err != nil {
		logAudit(AuditEntry{Action: "CHECK", Image: req.Image, Decision: "DENY", Reason: "resolver_error"})
		json.NewEncoder(w).Encode(map[string]interface{}{"Allow": false, "Reason": "resolver_error"})
		return
	}
	var entry TrustEntry
	var exists bool
	db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(trustBucket).Get([]byte(digest))
		if v != nil { exists = true; json.Unmarshal(v, &entry) }
		return nil
	})
	decision := "DENY"; reason := ""
	if exists {
		if entry.RequireSignature {
			key, keyExists := ks.Get(entry.PublicKeyID)
			if !keyExists || key.Revoked {
				if globalPolicy.RevalidateOnRevoke { exists = false; reason = "key_revoked" }
			} else if key.Version != entry.KeyVersion && globalPolicy.RevalidateOnRotation {
				exists = false; reason = "key_rotated"
			}
		}
	} else { reason = "untrusted_digest" }
	if exists { decision = "ALLOW" }
	logAudit(AuditEntry{Action: "CHECK", Image: req.Image, Digest: digest, Decision: decision, Reason: reason})
	json.NewEncoder(w).Encode(map[string]interface{}{"Allow": exists, "Digest": digest, "Reason": reason})
}

// Minimal helpers
func importKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct { ID string `json:"id"`; Raw []byte `json:"raw"` }
	json.NewDecoder(r.Body).Decode(&req)
	fp, _ := fingerprintPEM(req.Raw)
	kr := KeyRecord{ID: req.ID, Raw: req.Raw, Fingerprint: fp, Version: 1, CreatedAt: time.Now()}
	if old, ok := ks.Get(req.ID); ok { kr.Version = old.Version + 1 }
	val, _ := json.Marshal(kr)
	db.Update(func(tx *bolt.Tx) error { return tx.Bucket(keysBucket).Put([]byte(req.ID), val) })
	ks.Set(kr); logAudit(AuditEntry{Action: "KEY_IMPORT", KeyID: kr.ID, KeyVersion: kr.Version, Decision: "ALLOW"})
}
func revokeKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct { ID string `json:"id"` }
	json.NewDecoder(r.Body).Decode(&req)
	kr, _ := ks.Get(req.ID); kr.Revoked = true; kr.RevokedAt = time.Now()
	val, _ := json.Marshal(kr)
	db.Update(func(tx *bolt.Tx) error { return tx.Bucket(keysBucket).Put([]byte(req.ID), val) })
	ks.Set(kr); logAudit(AuditEntry{Action: "KEY_REVOKE", KeyID: kr.ID, Decision: "ALLOW"})
}
func listKeysHandler(w http.ResponseWriter, r *http.Request) {
	var keys []KeyRecord
	ks.mu.RLock(); for _, v := range ks.keys { keys = append(keys, v) }; ks.mu.RUnlock()
	json.NewEncoder(w).Encode(keys)
}
func listTrustHandler(w http.ResponseWriter, r *http.Request) {
	var entries []TrustEntry
	db.View(func(tx *bolt.Tx) error { return tx.Bucket(trustBucket).ForEach(func(k, v []byte) error { var e TrustEntry; json.Unmarshal(v, &e); entries = append(entries, e); return nil }) })
	json.NewEncoder(w).Encode(entries)
}
func listAuditHandler(w http.ResponseWriter, r *http.Request) {
	var entries []AuditEntry
	db.View(func(tx *bolt.Tx) error { return tx.Bucket(auditBucket).ForEach(func(k, v []byte) error { var e AuditEntry; json.Unmarshal(v, &e); entries = append(entries, e); return nil }) })
	json.NewEncoder(w).Encode(entries)
}
func addTrustHandler(w http.ResponseWriter, r *http.Request) {
	var entry TrustEntry
	json.NewDecoder(r.Body).Decode(&entry)
	if entry.RequireSignature {
		ver, err := verifySignature(entry.Target, entry.Digest, entry.PublicKeyID)
		if err != nil { http.Error(w, err.Error(), 403); return }
		entry.SignatureVerified = true; entry.VerifiedAt = time.Now(); entry.KeyVersion = ver
	}
	entry.AddedAt = time.Now(); val, _ := json.Marshal(entry)
	db.Update(func(tx *bolt.Tx) error { return tx.Bucket(trustBucket).Put([]byte(entry.Digest), val) })
	logAudit(AuditEntry{Action: "TRUST_ADD", Image: entry.Target, Decision: "ALLOW"})
	w.WriteHeader(201)
}
func resolveDigest(image string) (string, error) {
	httpClient := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return net.Dial("unix", dockerSocket) }}}
	resp, err := httpClient.Get(fmt.Sprintf("http://localhost/images/%s/json", image)); if err != nil { return "", err }; defer resp.Body.Close()
	var info struct { RepoDigests []string `json:"RepoDigests"`; Id string `json:"Id"` }
	json.NewDecoder(resp.Body).Decode(&info); digest := info.Id
	if len(info.RepoDigests) > 0 { parts := strings.Split(info.RepoDigests[0], "@"); if len(parts) == 2 { digest = parts[1] } }
	if !strings.HasPrefix(digest, "sha256:") { digest = "sha256:" + digest }; return digest, nil
}
func removeTrustHandler(w http.ResponseWriter, r *http.Request) {
	var req struct { Target string `json:"target"` }
	json.NewDecoder(r.Body).Decode(&req)
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(trustBucket)
		return b.ForEach(func(k, v []byte) error {
			var entry TrustEntry; json.Unmarshal(v, &entry)
			if entry.Target == req.Target { b.Delete(k) }
			return nil
		})
	})
}
func healthHandler(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(map[string]interface{}{"healthy": true, "v": "0.6.0"}) }
