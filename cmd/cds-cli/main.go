// cmd/cds-cli/main.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const daemonSocketPath = "/run/cds-daemon.sock"

// createUDSClient creates a client that can communicate with our daemon's socket.
func createUDSClient() *http.Client {
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", daemonSocketPath)
		},
	}
	return &http.Client{Transport: transport}
}

var rootCmd = &cobra.Command{
	Use:   "cds-cli",
	Short: "A CLI tool to interact with the CDS (Container Defense System) daemon.",
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage trusted image digests",
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new image digest to the trust database",
	RunE: func(cmd *cobra.Command, args []string) error {
		image, _ := cmd.Flags().GetString("image")
		digest, _ := cmd.Flags().GetString("digest")
		ttlStr, _ := cmd.Flags().GetString("ttl")

		ttlDuration, err := time.ParseDuration(ttlStr)
		if err != nil {
			return fmt.Errorf("invalid TTL duration: %w", err)
		}
		ttl := time.Now().Add(ttlDuration)

		fmt.Printf("Adding trust for image '%s' with digest '%s' and TTL '%s'...
", image, digest, ttl.Format(time.RFC3339))

		// Prepare the data to be sent to the daemon
		entry := map[string]interface{}{"image": image, "digest": digest, "ttl": ttl}
		body, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}

		// Send the request to the daemon via the UNIX socket
		client := createUDSClient()
		resp, err := client.Post("http://unix/trust/add", "application/json", bytes.NewBuffer(body))
		if err != nil {
			return fmt.Errorf("error communicating with daemon: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("daemon returned an error: %s", resp.Status)
		}

		fmt.Println("Trust added successfully.")
		return nil
	},
}

func init() {
	// Flags for the 'add' command
	addCmd.Flags().String("image", "", "Image name and tag (e.g., nginx:1.21)")
	addCmd.Flags().String("digest", "", "The full sha256 digest of the image")
	addCmd.Flags().String("ttl", "720h", "Trust duration from now (e.g., '24h', '30d' which is 720h)")
	addCmd.MarkFlagRequired("image")
	addCmd.MarkFlagRequired("digest")

	// Add subcommands
	trustCmd.AddCommand(addCmd)
	rootCmd.AddCommand(trustCmd)
	// TODO: Add 'list', 'revoke', and 'status' commands here.
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
