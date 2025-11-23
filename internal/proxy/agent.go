package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lonepie/reverse-soxy/internal/logger"
)

type session struct {
	targetConn net.Conn
	incoming   chan []byte
	ready      chan struct{}
}

var (
	sessionsMu  sync.Mutex
	sessionsMap = make(map[uint32]*session)
)

// DefaultMaxRetries is the default number of times to retry connecting before giving up
const DefaultMaxRetries = 10

// RunAgentRelay connects to the proxy via a relay server
func RunAgentRelay(relayAddr, secret string, maxRetries int) {
	// Use default value if maxRetries is not positive
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}

	retryCount := 0

	for {
		rawConn, err := net.Dial("tcp", relayAddr)
		if err != nil {
			retryCount++
			logger.Error("AgentRelay dial failed: %v (attempt %d/%d)", err, retryCount, maxRetries)
			if retryCount >= maxRetries {
				logger.Info("Maximum retry attempts (%d) reached, exiting", maxRetries)
				return
			}
			time.Sleep(5 * time.Second)
			continue
		}
		// send fixed 8-byte header
		hdr := []byte("AGENT   ")
		if _, err := rawConn.Write(hdr); err != nil {
			rawConn.Close()
			logger.Error("AgentRelay header send error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if err := answerRelayChallenge(rawConn, secret); err != nil {
			rawConn.Close()
			logger.Error("AgentRelay auth failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		// secure handshake
		secureConn, err := NewSecureClientConn(rawConn, secret)
		if err != nil {
			logger.Error("AgentRelay handshake failed: %v", err)
			rawConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		logger.Info("Agent connected via relay %s", relayAddr)
		// handle tunnel until error
		handleTunnelReadsServer(secureConn)
		secureConn.Close()
		time.Sleep(5 * time.Second)
	}
}

// RunAgent initiates a direct secure connection to the proxy with authentication/encryption
// If maxRetries <= 0, it will use DefaultMaxRetries
func RunAgent(proxyAddr, secret string, maxRetries int) {
	// Use default value if maxRetries is not positive
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}

	retryCount := 0

	// continuously dial and maintain tunnel
	for retryCount < maxRetries {
		rawConn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			retryCount++
			logger.Error("Agent connection failed: %v (attempt %d/%d)", err, retryCount, maxRetries)

			if retryCount >= maxRetries {
				logger.Info("Maximum retry attempts (%d) reached, exiting", maxRetries)
				return
			}

			time.Sleep(5 * time.Second)
			continue
		}

		// Reset retry counter on successful connection
		retryCount = 0
		// TCP optimizations
		if tcpConn, ok := rawConn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
		// secure handshake
		secureConn, err := NewSecureClientConn(rawConn, secret)
		if err != nil {
			logger.Error("Secure handshake failed: %v", err)
			rawConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		logger.Info("Agent connected to laptop")
		// handle tunnel reads until error
		handleTunnelReadsServer(secureConn)
		logger.Info("Agent disconnected, retrying in 5s")
		secureConn.Close()
		time.Sleep(5 * time.Second)

		// Increment retry counter for disconnection
		retryCount++
		logger.Info("Reconnection attempt %d/%d", retryCount, maxRetries)

		if retryCount >= maxRetries {
			logger.Info("Maximum retry attempts (%d) reached, exiting", maxRetries)
			return
		}
	}
}

func handleTunnelReadsServer(tunnel net.Conn) {
	logger.Info("Starting to read from tunnel")
	for {
		logger.Debug("Waiting for tunnel header...")
		header := make([]byte, 6)
		_, err := io.ReadFull(tunnel, header)
		if err != nil {
			logger.Info("tunnel read error:", err)
			return
		}
		sessID := binary.BigEndian.Uint32(header[:4])
		logger.Debug("Read header - session ID: %08x", sessID)
		length := binary.BigEndian.Uint16(header[4:6])
		logger.Debug("Expected payload length: %d", length)

		sessionsMu.Lock()
		sess, ok := sessionsMap[sessID]
		sessionsMu.Unlock()
		if !ok {
			// First message for this session: target string
			targetBuf := make([]byte, length)
			_, err = io.ReadFull(tunnel, targetBuf)
			if err != nil {
				logger.Error("Failed to read target address: %v", err)
				continue
			}
			target := string(targetBuf)
			logger.Info("session %08x connecting to %s", sessID, target)

			tgtConn, err := net.Dial("tcp", target)
			if err != nil {
				logger.Error("session %08x dial failed: %v", sessID, err)
				continue
			}
			sess = &session{
				targetConn: tgtConn,
				incoming:   make(chan []byte, 10),
				ready:      make(chan struct{}),
			}
			sessionsMu.Lock()
			sessionsMap[sessID] = sess
			sessionsMu.Unlock()
			close(sess.ready)
			go handleSession(sessID, sess, tunnel)
			continue // go to next header, do not expect payload for this header
		}

		// Existing session: treat as payload
		select {
		case <-sess.ready:
			logger.Debug("session %08x is ready to receive payload", sessID)
		case <-time.After(2 * time.Second):
			logger.Debug("session %08x timed out waiting for ready", sessID)
			continue
		}

		logger.Debug("about to read %d bytes of payload for session %08x", length, sessID)
		buf := make([]byte, length)
		bytesRead := 0
		for bytesRead < int(length) {
			n, err := tunnel.Read(buf[bytesRead:])
			logger.Debug("Read returned %d bytes, err=%v", n, err)
			logger.Debug("Bytes read so far (%d/%d): %x", bytesRead+n, length, buf[:bytesRead+n])
			if n > 0 {
				bytesRead += n
			}
			if err != nil {
				logger.Error("session %08x payload read error after %d bytes: %v", sessID, bytesRead, err)
				return
			}
		}
		logger.Debug("finished reading payload for session %08x", sessID)
		logger.Debug("session %08x received %d bytes payload: %x", sessID, length, buf)
		sess.incoming <- buf
	}
}

var serverTunnelWriteMu sync.Mutex

func handleSession(sessID uint32, sess *session, tunnel net.Conn) {
	defer sess.targetConn.Close()
	defer func() {
		sessionsMu.Lock()
		delete(sessionsMap, sessID)
		sessionsMu.Unlock()
		close(sess.incoming)
	}()

	go func() {
		buf := make([]byte, 4096)
		header := make([]byte, 6)
		binary.BigEndian.PutUint32(header[:4], sessID)
		for {
			n, err := sess.targetConn.Read(buf)
			if err != nil {
				logger.Debug("session %08x closed by target", sessID)
				return
			}
			binary.BigEndian.PutUint16(header[4:], uint16(n))
			serverTunnelWriteMu.Lock()
			tunnel.Write(header)
			tunnel.Write(buf[:n])
			serverTunnelWriteMu.Unlock()
			logger.Debug("session %08x sent %d bytes to tunnel, payload: %s", sessID, n, string(buf[:n]))
		}
	}()

	for data := range sess.incoming {
		logger.Debug("session %08x writing %d bytes to target", sessID, len(data))
		n, err := sess.targetConn.Write(data)
		if err != nil {
			logger.Error("session %08x write to target failed: %v", sessID, err)
			break
		}
		logger.Debug("session %08x forwarded %d bytes to target", sessID, n)
	}
}
