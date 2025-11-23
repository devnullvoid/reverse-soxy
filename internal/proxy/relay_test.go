package proxy

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestRegisterProxy(t *testing.T) {
	// reset registry
	regMu.Lock()
	registry = nil
	regMu.Unlock()
	// simulate a proxy registration
	c1, c2 := net.Pipe()
	// run registerProxy in goroutine to avoid blocking
	go registerProxy(c1)
	// allow goroutine to append
	time.Sleep(10 * time.Millisecond)
	regMu.Lock()
	if len(registry) != 1 {
		t.Fatalf("expected registry length 1, got %d", len(registry))
	}
	if registry[0] != c1 {
		t.Fatalf("expected registry[0] to be c1")
	}
	// cleanup
	registry = nil
	regMu.Unlock()
	c1.Close()
	c2.Close()
}

func TestHandleRelayConnRegister(t *testing.T) {
	// reset registry
	regMu.Lock()
	registry = nil
	regMu.Unlock()
	client, server := net.Pipe()
	// start handler before writing to avoid blocking
	go handleRelayConn(server, "secret")
	// write REGISTER header (8 bytes)
	if _, err := client.Write([]byte("REGISTER")); err != nil {
		t.Fatalf("failed to write header: %v", err)
	}
	if err := answerRelayChallenge(client, "secret"); err != nil {
		t.Fatalf("challenge response failed: %v", err)
	}
	// allow time for processing
	time.Sleep(10 * time.Millisecond)
	regMu.Lock()
	if len(registry) != 1 {
		t.Fatalf("expected registry length 1 after handleRelayConn, got %d", len(registry))
	}
	if registry[0] != server {
		t.Fatalf("expected registered conn to be server")
	}
	t.Log("Registry registered successfully")
	regMu.Unlock()
	client.Close()
	server.Close()
}

func TestVerifyRelayPeerRejectsWrongSecret(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- verifyRelayPeer(server, "secret")
	}()

	if err := answerRelayChallenge(client, "wrong"); err != nil {
		t.Fatalf("answerRelayChallenge failed: %v", err)
	}

	err := <-errCh
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("expected errAuthFailed, got %v", err)
	}
}

func TestRelayChallengeSuccess(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- verifyRelayPeer(server, "secret")
	}()

	if err := answerRelayChallenge(client, "secret"); err != nil {
		t.Fatalf("answerRelayChallenge failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("verifyRelayPeer returned error: %v", err)
	}
}
