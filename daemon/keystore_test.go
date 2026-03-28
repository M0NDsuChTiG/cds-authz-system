package main

import (
	"testing"
	"time"
)

func TestKeyStore(t *testing.T) {
	ks := &KeyStore{keys: make(map[string]KeyRecord)}
	
	key := KeyRecord{
		ID:          "test-key",
		Raw:         []byte("dummy-key-content"),
		Fingerprint: "abc",
		Version:     1,
		CreatedAt:   time.Now(),
	}

	// Test Set
	ks.Set(key)

	// Test Get
	retrieved, ok := ks.Get("test-key")
	if !ok {
		t.Fatal("expected key to be found")
	}
	if retrieved.ID != "test-key" {
		t.Errorf("expected ID 'test-key', got '%s'", retrieved.ID)
	}

	// Test non-existent
	_, ok = ks.Get("non-existent")
	if ok {
		t.Error("expected non-existent key to not be found")
	}
}
