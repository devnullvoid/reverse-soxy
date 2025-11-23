package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lonepie/reverse-soxy/internal/logger"
)

var (
	regMu    sync.Mutex
	registry []net.Conn
)

// RunRelay starts a relay server on the given port, accepting registrations and agent connections.
func RunRelay(listenPort int, secret string) {
	addr := fmt.Sprintf(":%d", listenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatalf("Relay listen error: %v", err)
	}
	logger.Info("Relay listening on %s", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Relay accept error: %v", err)
			continue
		}
		go handleRelayConn(conn, secret)
	}
}

func handleRelayConn(conn net.Conn, secret string) {
	defer conn.Close()
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		logger.Error("Relay header read error: %v", err)
		return
	}
	header := strings.TrimSpace(string(hdr))
	switch header {
	case "REGISTER":
		if err := verifyRelayPeer(conn, secret); err != nil {
			logger.Error("Relay REGISTER auth failed: %v", err)
			return
		}
		registerProxy(conn)
	case "AGENT":
		if err := verifyRelayPeer(conn, secret); err != nil {
			logger.Error("Relay AGENT auth failed: %v", err)
			return
		}
		handleAgent(conn)
	default:
		logger.Error("Unknown relay header: %s", header)
	}
}

const relayAuthTimeout = 10 * time.Second

func verifyRelayPeer(conn net.Conn, secret string) error {
	if secret == "" {
		return errAuthFailed
	}
	if err := conn.SetDeadline(time.Now().Add(relayAuthTimeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	challenge := make([]byte, handshakeChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	if _, err := conn.Write(challenge); err != nil {
		return err
	}

	expected := hmac.New(sha256.New, deriveKey(secret))
	expected.Write(challenge)

	response := make([]byte, expected.Size())
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if !hmac.Equal(response, expected.Sum(nil)) {
		return errAuthFailed
	}

	return nil
}

func answerRelayChallenge(conn net.Conn, secret string) error {
	if secret == "" {
		return errAuthFailed
	}
	if err := conn.SetDeadline(time.Now().Add(relayAuthTimeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	challenge := make([]byte, handshakeChallengeSize)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return err
	}

	mac := hmac.New(sha256.New, deriveKey(secret))
	mac.Write(challenge)

	if _, err := conn.Write(mac.Sum(nil)); err != nil {
		return err
	}

	return nil
}

func registerProxy(conn net.Conn) {
	regMu.Lock()
	registry = append(registry, conn)
	regMu.Unlock()
	logger.Info("Proxy registered to relay")
	select {} // hold open
}

func handleAgent(conn net.Conn) {
	regMu.Lock()
	if len(registry) == 0 {
		regMu.Unlock()
		logger.Error("No registered proxies available")
		return
	}
	proxyConn := registry[0]
	registry = registry[1:]
	regMu.Unlock()
	// copy from agent to proxy with debug logging
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				logger.Debug("Relay agent->proxy payload: %x", buf[:n])
				if _, werr := proxyConn.Write(buf[:n]); werr != nil {
					logger.Error("Relay write agent->proxy error: %v", werr)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					logger.Error("Relay agent->proxy read error: %v", err)
				}
				return
			}
		}
	}()
	// copy from proxy to agent with debug logging
	buf := make([]byte, 4096)
	for {
		n, err := proxyConn.Read(buf)
		if n > 0 {
			logger.Debug("Relay proxy->agent payload: %x", buf[:n])
			if _, werr := conn.Write(buf[:n]); werr != nil {
				logger.Error("Relay write proxy->agent error: %v", werr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				logger.Error("Relay proxy->agent read error: %v", err)
			}
			return
		}
	}
}

// RunRegister connects to a relay server and registers as a proxy.
func RunRegister(relayAddr, secret string) {
	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		logger.Fatalf("Register dial error: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("REGISTER"))
	if err := answerRelayChallenge(conn, secret); err != nil {
		logger.Fatalf("Register auth failed: %v", err)
	}
	logger.Info("Registered with relay %s", relayAddr)
	select {} // hold open
}
