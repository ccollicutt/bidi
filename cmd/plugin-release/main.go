// plugin-release signs a platform artifact and immutable manifest offline.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/ccollicutt/bidi/internal/plugin"
)

func main() {
	keygen := flag.String("keygen", "", "write an Ed25519 signing key to this path and its public key to PATH.pub")
	keyFile := flag.String("key", "", "base64 Ed25519 private key file")
	manifestFile := flag.String("manifest", "", "unsigned manifest JSON path")
	artifactFile := flag.String("artifact", "", "native executable path")
	outputFile := flag.String("out", "", "signed manifest output path")
	flag.Parse()
	if *keygen != "" {
		if err := generateKey(*keygen); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *keyFile == "" || *manifestFile == "" || *artifactFile == "" || *outputFile == "" {
		log.Fatal("-key, -manifest, -artifact, and -out are required")
	}
	keyRaw, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(stringTrim(keyRaw))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		log.Fatal("invalid private key")
	}
	raw, err := os.ReadFile(*manifestFile)
	if err != nil {
		log.Fatal(err)
	}
	m, err := plugin.Parse(raw)
	if err != nil {
		log.Fatal(err)
	}
	if m.Signature != "" {
		log.Fatal("manifest already signed")
	}
	artifact, err := os.ReadFile(*artifactFile)
	if err != nil {
		log.Fatal(err)
	}
	if len(artifact) == 0 || int64(len(artifact)) > plugin.MaxArtifactSize {
		log.Fatal("artifact size outside limit")
	}
	a := plugin.Artifact{OS: runtime.GOOS, Arch: runtime.GOARCH, Format: "elf", Size: int64(len(artifact)), SHA256: plugin.Hash(artifact)}
	m.Artifacts = []plugin.Artifact{a}
	if err := m.Sign(ed25519.PrivateKey(key)); err != nil {
		log.Fatal(err)
	}
	if err := m.Verify(map[string]ed25519.PublicKey{m.PublisherKeyID: ed25519.PrivateKey(key).Public().(ed25519.PublicKey)}, nil, m.Capabilities.FilesystemRead, m.Capabilities.Network); err != nil {
		log.Fatal(err)
	}
	signed, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*outputFile, append(signed, '\n'), 0644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("signed %s %s %s/%s %s\n", m.PluginID, m.Version, a.OS, a.Arch, a.SHA256)
}
func stringTrim(b []byte) string {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return string(b[start:end])
}

func generateKey(path string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	private, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer private.Close()
	public, err := os.OpenFile(path+".pub", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		os.Remove(path)
		return err
	}
	defer public.Close()
	if _, err = private.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); err == nil {
		_, err = public.WriteString(base64.StdEncoding.EncodeToString(pub) + "\n")
	}
	if err != nil {
		os.Remove(path)
		os.Remove(path + ".pub")
	}
	return err
}
