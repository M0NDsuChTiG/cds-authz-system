// plugin/main.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/docker/go-plugins-helpers/authorization"
)

const daemonSocketPath = "/run/cds-daemon.sock"

func main() {
	// The authorization.NewHandler abstracts away the low-level details.
	// It will create a socket at /run/docker/plugins/cds-authz.sock
	// and handle the HTTP serving over that socket.
	h := authorization.NewHandler(authzHandler)
	if err := h.ServeUnix("cds-authz", 0); err != nil {
		panic(err)
	}
}

// authzHandler is the callback that Docker invokes for authorization.
func authzHandler(req authorization.Request) authorization.Response {
	// We only care about container creation. Allow all other operations.
	if req.RequestMethod != "POST" || !strings.Contains(req.RequestURI, "/containers/create") {
		return authorization.Response{Allow: true}
	}

	// Extract the image name from the request body.
	var bodyData struct {
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(req.RequestBody, &bodyData); err != nil {
		return authorization.Response{Allow: false, Msg: fmt.Sprintf("Error unmarshalling request body: %v", err)}
	}

	// In a real plugin, you would now resolve this image name (e.g., "alpine:latest")
	// to its immutable digest (e.g., "sha256:...") by calling the Docker daemon's API.
	// For this skeleton, we will assume the Image field IS the digest to keep it simple.
	digest := bodyData.Image
	if digest == "" {
		return authorization.Response{Allow: false, Msg: "Image digest could not be determined from request."}
	}

	// --- Query the cds-daemon ---
	// Create a custom http.Client that communicates over our daemon's UNIX socket.
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", daemonSocketPath)
		},
	}
	client := &http.Client{Transport: transport}

	// Prepare the request body for the daemon.
	daemonReqBody, err := json.Marshal(map[string]string{"digest": digest})
	if err != nil {
		return authorization.Response{Allow: false, Msg: fmt.Sprintf("Error marshalling daemon request: %v", err)}
	}

	// The hostname 'unix' is arbitrary, it's ignored by the UDS transport.
	resp, err := client.Post("http://unix/trust/check", "application/json", bytes.NewBuffer(daemonReqBody))
	if err != nil {
		// This is a fail-closed scenario. If we can't reach the daemon, we deny.
		return authorization.Response{Allow: false, Msg: fmt.Sprintf("DENY: daemon check failed (fail-closed): %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The daemon explicitly denied the request.
		return authorization.Response{Allow: false, Msg: fmt.Sprintf("DENY: daemon rejected trust (fail-closed): %s", resp.Status)}
	}

	// If we get here, the daemon responded with HTTP 200 OK, so we allow.
	return authorization.Response{Allow: true}
}
