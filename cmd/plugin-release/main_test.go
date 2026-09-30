package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeygenRefusesExistingFiles(t *testing.T) {
	for _, existing := range []string{"private", "public"} {
		t.Run(existing, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "publisher.key")
			target := path
			if existing == "public" {
				target += ".pub"
			}
			if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := generateKey(path); err == nil {
				t.Fatal("overwrote existing key")
			}
			raw, err := os.ReadFile(target)
			if err != nil || string(raw) != "keep" {
				t.Fatalf("existing key changed: %q %v", raw, err)
			}
			if existing == "public" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("left private key: %v", err)
				}
			}
		})
	}
	path := filepath.Join(t.TempDir(), "publisher.key")
	if err := generateKey(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode: %v", info.Mode())
	}
}
