package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

func TestDeriveKeyConsistent(t *testing.T) {
	k1 := deriveKey("secret")
	k2 := deriveKey("secret")
	if !bytes.Equal(k1, k2) {
		t.Errorf("deriveKey inconsistent: %x vs %x", k1, k2)
	}
}

func TestSecureConnRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	secret := "shared"
	var sc, ss net.Conn
	var errC, errS error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		sc, errC = NewSecureClientConn(c1, secret)
		wg.Done()
	}()
	go func() {
		ss, errS = NewSecureServerConn(c2, secret)
		wg.Done()
	}()
	wg.Wait()
	if errC != nil {
		t.Fatalf("NewSecureClientConn error: %v", errC)
	}
	if errS != nil {
		t.Fatalf("NewSecureServerConn error: %v", errS)
	}

	// Client -> Server
	msg := []byte("hello world")
	go func() {
		if _, err := sc.Write(msg); err != nil {
			t.Errorf("client Write error: %v", err)
		}
	}()
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(ss, buf); err != nil {
		t.Fatalf("server Read error: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("mismatch: got %s, want %s", buf, msg)
	}

	// Server -> Client
	resp := []byte("response")
	go func() {
		if _, err := ss.Write(resp); err != nil {
			t.Errorf("server Write error: %v", err)
		}
	}()
	buf2 := make([]byte, len(resp))
	if _, err := io.ReadFull(sc, buf2); err != nil {
		t.Fatalf("client Read error: %v", err)
	}
	if !bytes.Equal(resp, buf2) {
		t.Errorf("mismatch: got %s, want %s", buf2, resp)
	}
}

func TestSecureHandshakeRejectsInvalidMAC(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	secret := "shared"
	errCh := make(chan error, 1)
	go func() {
		_, err := NewSecureServerConn(server, secret)
		errCh <- err
	}()

	challenge := make([]byte, sha256.Size)
	if _, err := io.ReadFull(client, challenge); err != nil {
		t.Fatalf("failed to read challenge: %v", err)
	}

	// Reuse a MAC from a stale challenge to simulate replay.
	staleChallenge := bytes.Repeat([]byte{0x42}, len(challenge))
	mac := hmac.New(sha256.New, deriveKey(secret))
	mac.Write(staleChallenge)
	replayed := mac.Sum(nil)
	if _, err := client.Write(replayed); err != nil {
		t.Fatalf("failed to write replayed mac: %v", err)
	}
	err := <-errCh
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("expected errAuthFailed, got %v", err)
	}
}
