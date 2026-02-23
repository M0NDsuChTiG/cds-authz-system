package main

import (
	"bytes"
	"context" // Required for DialContext signature with Go 1.19
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath" // Required for filepath.Dir
	"strings"
	"time"
)

const (
	pluginSocket = "/run/docker/plugins/cds-authz.sock" // Plugin now listens on UDS
	cdsSocket    = "/run/cds.sock"
	dockerSocket = "/var/run/docker.sock"
	timeout      = 2 * time.Second
)

// AuthZRequest is the payload sent by Docker to the plugin.
type AuthZRequest struct {
	RequestURI  string          `json:"RequestURI"`
	RequestBody json.RawMessage `json:"RequestBody"`
}

// AuthZResponse is the payload sent by the plugin back to Docker.
type AuthZResponse struct {
	Allow bool   `json:"Allow"`
	Msg   string `json:"Msg,omitempty"`
	Err   string `json:"Err,omitempty"` // Added missing field
}

// Simplified struct for container creation to extract the image name.
type ContainerCreateRequest struct {
	Image string `json:"Image"`
}

// createUDSClient creates an http.Client that communicates over a given UNIX domain socket.
// Context is not used directly in DialTimeout in Go 1.19, so simplified.
func createUDSClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { // Kept context as it's part of the standard signature
				return net.DialTimeout("unix", socketPath, timeout)
			},
		},
		Timeout: timeout,
	}
}

// resolveDigest connects to the Docker daemon to resolve an image name/tag to a digest.
func resolveDigest(imageName string) (string, error) {
	log.Printf("Resolving digest for image: %s", imageName)
	dockerClient := createUDSClient(dockerSocket)

	// URL encode the image name to handle special characters (e.g., in tags or registries)
	encodedImageName := strings.ReplaceAll(imageName, "/", "%2F") // Use ReplaceAll for Go 1.19+

	reqURL := fmt.Sprintf("http://unix/images/%s/json", encodedImageName)

	resp, err := dockerClient.Get(reqURL)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Docker daemon for digest resolution: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read body for more error context
		return "", fmt.Errorf("Docker daemon returned status %s for image '%s': %s", resp.Status, imageName, string(bodyBytes))
	}

	var result struct {
		RepoDigests []string `json:"RepoDigests"`
		ID          string   `json:"Id"` // Fallback to Image ID if RepoDigests is empty
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response from Docker daemon: %w", err)
	}

	if len(result.RepoDigests) > 0 {
		// RepoDigests are in the format "registry/repo@sha256:digest"
		parts := strings.Split(result.RepoDigests[0], "@")
		if len(parts) == 2 {
			log.Printf("Resolved image '%s' to digest '%s'", imageName, parts[1])
			return parts[1], nil
		}
	}
	
	// Fallback for images without a RepoDigest (e.g., built locally without a push)
	if result.ID != "" {
		log.Printf("Resolved image '%s' to local ID '%s'", imageName, result.ID)
		return result.ID, nil // Return image ID as digest for locally built images
	}

	return "", fmt.Errorf("could not find a digest for image '%s'", imageName)
}

// queryDaemon sends a digest to the cds-daemon and returns the decision.
func queryDaemon(digest string) (bool, string) {
	cdsClient := createUDSClient(cdsSocket)

	payload, err := json.Marshal(map[string]string{"digest": digest})
	if err != nil {
		log.Printf("Internal error: failed marshalling daemon request: %v", err)
		return false, "CDS: Internal plugin error"
	}

	resp, err := cdsClient.Post("http://unix/v1/check", "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Daemon communication error: %v", err)
		return false, "CDS: Daemon unreachable" // Fail-closed
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Daemon response error: %v", err)
		return false, "CDS: Invalid daemon response" // Fail-closed
	}

	decision, _ := result["decision"].(string)
	reason, _ := result["reason"].(string)

	if decision == "ALLOW" {
		return true, "verified"
	}
	return false, reason
}

// --- Docker AuthZ Plugin API Handlers ---

func activateHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received activate request from Docker daemon")
	w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.2+json")
	json.NewEncoder(w).Encode(map[string][]string{"Implements": {"authz"}})
}

func authResHandler(w http.ResponseWriter, r *http.Request) {
	// Docker sends an AuthZRes after a successful AuthZReq.
	// We don't need to do anything with the response from the daemon, just allow.
	json.NewEncoder(w).Encode(AuthZResponse{Allow: true})
}


func authHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	var req AuthZRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Failed to unmarshal request body", http.StatusBadRequest)
		return
	}

	// We only care about container creation requests. Allow everything else.
	if !strings.Contains(req.RequestURI, "/containers/create") { // Use Contains for more robustness
		json.NewEncoder(w).Encode(AuthZResponse{Allow: true})
		return
	}

	var containerReq ContainerCreateRequest
	if err := json.Unmarshal(req.RequestBody, &containerReq); err != nil {
		sendAuthZResponse(w, false, "Invalid container create request body.")
		return
	}
	
	imageName := containerReq.Image
	log.Printf("Handling container create request for image: %s", imageName)

	digest, err := resolveDigest(imageName)
	if err != nil {
		log.Printf("Digest resolution failed for '%s': %v", imageName, err)
		sendAuthZResponse(w, false, fmt.Sprintf("digest resolution failed for '%s': %v", imageName, err))
		return
	}

	allow, reason := queryDaemon(digest)
	sendAuthZResponse(w, allow, reason)
}

func sendAuthZResponse(w http.ResponseWriter, allow bool, msg string) {
	resp := AuthZResponse{
		Allow: allow,
		Msg:   msg,
	}
	if !allow {
		resp.Err = msg // Populate Err field on deny
	}
	w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.2+json")
	json.NewEncoder(w).Encode(resp)
}


func main() {
	// Clean up any old socket file
	if err := os.RemoveAll(pluginSocket); err != nil {
		log.Fatalf("Error removing old plugin socket %s: %v", pluginSocket, err)
	}
	// Ensure the directory for plugin sockets exists
	pluginDir := filepath.Dir(pluginSocket)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		log.Fatalf("Error creating plugin socket directory %s: %v", pluginDir, err)
	}
	// Explicitly set permissions for the directory, in case MkdirAll is affected by umask or other factors
	if err := os.Chmod(pluginDir, 0755); err != nil {
		log.Fatalf("Error setting permissions on plugin socket directory %s: %v", pluginDir, err)
	}

	listener, err := net.Listen("unix", pluginSocket)
	if err != nil {
		log.Fatalf("Error listening on unix socket %s: %v", pluginSocket, err)
	}
	// Set correct permissions on the socket
	if err := os.Chmod(pluginSocket, 0600); err != nil {
		log.Fatalf("Error setting socket permissions: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/AuthZPlugin.Activate", activateHandler)
	mux.HandleFunc("/AuthZPlugin.AuthZReq", authHandler)
	mux.HandleFunc("/AuthZPlugin.AuthZRes", authResHandler)

	log.Println("CDS AuthZ plugin listening on", pluginSocket)
	if err := http.Serve(listener, mux); err != nil {
		log.Fatalf("http.Serve error: %v", err)
	}
}
