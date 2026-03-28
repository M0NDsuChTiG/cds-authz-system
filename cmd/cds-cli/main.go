package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const socketPath = "/run/cds/cds.sock"

func getClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

var rootCmd = &cobra.Command{
	Use:   "cds-cli",
	Short: "CDS CLI tool for managing trust and keys",
}

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage keys",
}

var importKeyCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a public key",
	Run: func(cmd *cobra.Command, args []string) {
		id, _ := cmd.Flags().GetString("id")
		path, _ := cmd.Flags().GetString("path")
		if id == "" || path == "" {
			fmt.Println("Error: --id and --path are required")
			return
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("Error reading key file: %v\n", err)
			return
		}

		req := map[string]interface{}{"id": id, "raw": raw}
		body, _ := json.Marshal(req)
		
		client := getClient()
		resp, err := client.Post("http://localhost/v1/keys/import", "application/json", bytes.NewBuffer(body))
		if err != nil {
			fmt.Printf("Error calling daemon: %v\n", err)
			return
		}
		defer resp.Body.Close()
		fmt.Printf("Key '%s' imported successfully (Status: %d)\n", id, resp.StatusCode)
	},
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage trust records",
}

var addTrustCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a trust record for an image",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Error: image argument is required")
			return
		}
		image := args[0]
		keyID, _ := cmd.Flags().GetString("key-id")
		digest, _ := cmd.Flags().GetString("digest")
		ttl, _ := cmd.Flags().GetDuration("ttl")

		req := map[string]interface{}{
			"target": image,
			"digest": digest,
			"public_key_id": keyID,
		}
		if ttl > 0 {
			req["expires_at"] = time.Now().Add(ttl)
		}

		body, _ := json.Marshal(req)
		client := getClient()
		resp, err := client.Post("http://localhost/v1/trust/add", "application/json", bytes.NewBuffer(body))
		if err != nil {
			fmt.Printf("Error calling daemon: %v\n", err)
			return
		}
		defer resp.Body.Close()
		fmt.Printf("Trust added for image '%s' (Status: %d)\n", image, resp.StatusCode)
	},
}

var listKeysCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys",
	Run: func(cmd *cobra.Command, args []string) {
		client := getClient()
		resp, err := client.Get("http://localhost/v1/keys")
		if err != nil {
			fmt.Printf("Error calling daemon: %v\n", err)
			return
		}
		defer resp.Body.Close()
		io.Copy(os.Stdout, resp.Body)
		fmt.Println()
	},
}

var listTrustCmd = &cobra.Command{
	Use:   "list",
	Short: "List all trust records",
	Run: func(cmd *cobra.Command, args []string) {
		client := getClient()
		resp, err := client.Get("http://localhost/v1/trust")
		if err != nil {
			fmt.Printf("Error calling daemon: %v\n", err)
			return
		}
		defer resp.Body.Close()
		io.Copy(os.Stdout, resp.Body)
		fmt.Println()
	},
}

func main() {
	importKeyCmd.Flags().String("id", "", "Key ID")
	importKeyCmd.Flags().String("path", "", "Path to public key")
	
	addTrustCmd.Flags().String("key-id", "", "Key ID used for signature")
	addTrustCmd.Flags().String("digest", "", "Digest of the image")
	addTrustCmd.Flags().Duration("ttl", 0, "TTL for trust record (e.g. 24h)")

	keyCmd.AddCommand(importKeyCmd)
	keyCmd.AddCommand(listKeysCmd)
	trustCmd.AddCommand(addTrustCmd)
	trustCmd.AddCommand(listTrustCmd)
	
	rootCmd.AddCommand(keyCmd)
	rootCmd.AddCommand(trustCmd)
	
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
