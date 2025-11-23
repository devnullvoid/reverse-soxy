package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"

	"github.com/lonepie/reverse-soxy/internal/logger"
)

// socksListenAddr is set by RunClient
var socksListenAddr string

// tunnelListenPort is set by RunClient
var tunnelListenPort int

// tunnelSecret is used to authenticate and encrypt tunnel connections
var tunnelSecret string

var (
	tunnelConn    net.Conn
	tunnelWriteMu sync.Mutex
	tunnelMu      sync.Mutex
	clientSess    = make(map[uint32]net.Conn)
	clientMu      sync.Mutex
)

// RunProxy starts the SOCKS5 proxy frontend and tunnel listener.
func RunProxy(proxyAddr string, port int, secret string) {
	// configure addresses
	socksListenAddr = proxyAddr
	tunnelListenPort = port
	tunnelSecret = secret
	logger.Info("Listening for tunnel on port %d", tunnelListenPort)
	go startTunnelListener()

	ln, err := net.Listen("tcp", socksListenAddr)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Info("SOCKS5 proxy listening on %s", socksListenAddr)
	for {
		client, err := ln.Accept()
		if err != nil {
			logger.Println("Accept error:", err)
			continue
		}
		go handleSOCKS(client)
	}
}

func startTunnelListener() {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(tunnelListenPort))
	if err != nil {
		logger.Fatalf("Tunnel listener failed: %v", err)
	}
	for {
		rawConn, err := ln.Accept()
		if err != nil {
			logger.Fatal("Tunnel accept failed:", err)
		}
		// secure the tunnel connection
		secureConn, err := NewSecureServerConn(rawConn, tunnelSecret)
		if err != nil {
			logger.Error("Secure handshake failed: %v", err)
			rawConn.Close()
			continue
		}
		tunnelMu.Lock()
		if tunnelConn != nil {
			logger.Info("Closing previous tunnel connection")
			tunnelConn.Close() // This will cause the old goroutine to exit
		}
		tunnelConn = secureConn
		if tcpConn, ok := secureConn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}
		tunnelMu.Unlock()
		logger.Info("Tunnel connected from %v", secureConn.RemoteAddr())
		go handleTunnelReadsClient(secureConn)
	}
}

func handleSOCKS(client net.Conn) {
	buf := make([]byte, 262)
	// Step 1: Client greeting
	n, err := io.ReadAtLeast(client, buf, 2)
	if err != nil {
		logger.Error("SOCKS handshake failed: %v", err)
		client.Close()
		return
	}
	if buf[0] != 0x05 {
		logger.Error("Unsupported SOCKS version: %v", buf[0])
		client.Close()
		return
	}
	methods := buf[1]
	if n < int(2+methods) {
		_, err = io.ReadFull(client, buf[n:2+methods])
		if err != nil {
			logger.Error("SOCKS handshake method read failed: %v", err)
			client.Close()
			return
		}
	}
	// Step 2: Server selects 'no auth'
	_, err = client.Write([]byte{0x05, 0x00})
	if err != nil {
		logger.Error("Failed to write SOCKS5 method selection: %v", err)
		client.Close()
		return
	}

	// Step 3: Client connect request
	n, err = io.ReadAtLeast(client, buf, 5)
	if err != nil {
		logger.Error("SOCKS connect request failed: %v", err)
		client.Close()
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		logger.Error("Only SOCKS5 CONNECT supported")
		client.Close()
		return
	}
	addrType := buf[3]
	var target string
	addrLen := 0
	switch addrType {
	case 0x01: // IPv4
		addrLen = 4
	case 0x03: // Domain
		addrLen = int(buf[4]) + 1
	case 0x04: // IPv6
		addrLen = 16
	default:
		logger.Error("Unsupported address type: %v", addrType)
		client.Close()
		return
	}
	// Read the rest of the address/port if not already read
	reqLen := 4 + addrLen + 2
	if n < reqLen {
		_, err = io.ReadFull(client, buf[n:reqLen])
		if err != nil {
			logger.Error("SOCKS connect request addr/port read failed: %v", err)
			client.Close()
			return
		}
	}
	// Parse target
	switch addrType {
	case 0x01:
		ip := net.IP(buf[4:8])
		port := binary.BigEndian.Uint16(buf[8:10])
		target = fmt.Sprintf("%s:%d", ip.String(), port)
	case 0x03:
		hostLen := int(buf[4])
		host := string(buf[5 : 5+hostLen])
		port := binary.BigEndian.Uint16(buf[5+hostLen : 7+hostLen])
		target = fmt.Sprintf("%s:%d", host, port)
	case 0x04:
		ip := net.IP(buf[4:20])
		port := binary.BigEndian.Uint16(buf[20:22])
		target = fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	logger.Info("Request to %s", target)

	// Step 4: Send connect reply (success)
	reply := make([]byte, 10)
	reply[0] = 0x05 // version
	reply[1] = 0x00 // success
	reply[2] = 0x00 // reserved
	reply[3] = 0x01 // IPv4
	copy(reply[4:], net.ParseIP("127.0.0.1").To4())
	binary.BigEndian.PutUint16(reply[8:], 1080) // bound port
	_, err = client.Write(reply)
	if err != nil {
		logger.Error("Failed to write SOCKS5 connect reply: %v", err)
		client.Close()
		return
	}

	// Only now start session/tunnel forwarding
	sessID := rand.Uint32()
	tunnelMu.Lock()
	tunnelConnGlobal := tunnelConn
	if tunnelConnGlobal == nil {
		tunnelMu.Unlock()
		logger.Error("No tunnel connection available for session %08x", sessID)
		client.Close()
		return
	}
	// Send session header and target string to tunnel BEFORE starting forwarding
	header := make([]byte, 6)
	binary.BigEndian.PutUint32(header[:4], sessID)
	binary.BigEndian.PutUint16(header[4:], uint16(len(target)))
	_, err = tunnelConnGlobal.Write(header)
	if err != nil {
		tunnelMu.Unlock()
		logger.Error("Failed to write session header: %v", err)
		client.Close()
		return
	}
	_, err = tunnelConnGlobal.Write([]byte(target))
	if err != nil {
		tunnelMu.Unlock()
		logger.Error("Failed to write target string: %v", err)
		client.Close()
		return
	}
	clientMu.Lock()
	clientSess[sessID] = client
	clientMu.Unlock()
	tunnelMu.Unlock()
	logger.Info("Tunnel connected from %v", tunnelConnGlobal.RemoteAddr())
	go forwardClientToTunnel(tunnelConnGlobal, client, sessID)
}

func writeFull(conn net.Conn, data []byte) error {
	total := 0
	for total < len(data) {
		n, err := conn.Write(data[total:])
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

func forwardClientToTunnel(dst net.Conn, src net.Conn, sessID uint32) {
	buf := make([]byte, 4096)
	header := make([]byte, 6)
	binary.BigEndian.PutUint32(header[:4], sessID)
	logger.Debug("tunnelConn pointer: %p, LocalAddr: %v, RemoteAddr: %v", dst, dst.LocalAddr(), dst.RemoteAddr())
	errorCh := make(chan error, 1)

	// Forward src (SOCKS client) -> dst (tunnel)
	go func() {
		for {
			logger.Debug("session %08x waiting to read from SOCKS client", sessID)
			n, err := src.Read(buf)
			if err != nil {
				logger.Debug("session %08x closed by client", sessID)
				errorCh <- err
				return
			}
			binary.BigEndian.PutUint16(header[4:], uint16(n))
			logger.Debug("session %08x preparing to send %d bytes. Payload:\n%s", sessID, n, string(buf[:n]))
			logger.Debug("Writing header+payload (%d bytes) to tunnel", n)
			tunnelWriteMu.Lock()
			if err = writeFull(dst, header); err != nil {
				tunnelWriteMu.Unlock()
				logger.Error("session %08x header+payload write failed: %v", sessID, err)
				errorCh <- err
				return
			}
			if err = writeFull(dst, buf[:n]); err != nil {
				tunnelWriteMu.Unlock()
				logger.Error("session %08x header+payload write failed: %v", sessID, err)
				errorCh <- err
				return
			}
			tunnelWriteMu.Unlock()
			logger.Debug("session %08x wrote header and %d payload bytes to tunnel", sessID, n)
		}
	}()

	// Wait for either direction to error/close
	err := <-errorCh
	logger.Info("session %08x closing, reason: %v", sessID, err)
	// Do NOT close the shared tunnel connection here; only close the SOCKS client connection.
	if src != nil {
		logger.Debug("Closing SOCKS client %p", src)
		err := src.Close()
		if err != nil {
			logger.Debug("Error closing SOCKS client: %v", err)
		} else {
			logger.Debug("SOCKS client closed successfully")
		}
	}
	clientMu.Lock()
	delete(clientSess, sessID)
	clientMu.Unlock()
}

func handleTunnelReadsClient(tunnel net.Conn) {
	header := make([]byte, 6)
	for {
		_, err := io.ReadFull(tunnel, header)
		if err != nil {
			logger.Println("Tunnel read error:", err)
			return
		}
		sessID := binary.BigEndian.Uint32(header[:4])
		length := binary.BigEndian.Uint16(header[4:6])
		buf := make([]byte, length)
		_, err = io.ReadFull(tunnel, buf)
		if err != nil {
			logger.Error("Payload read error for session %08x: %v", sessID, err)
			return
		}
		clientMu.Lock()
		client, ok := clientSess[sessID]
		clientMu.Unlock()
		if !ok {
			logger.Error("Received data for unknown or closed session %08x", sessID)
			continue
		}
		_, err = client.Write(buf)
		if err != nil {
			logger.Error("Write to SOCKS client for session %08x failed: %v", sessID, err)
			clientMu.Lock()
			delete(clientSess, sessID)
			clientMu.Unlock()
			_ = client.Close()
		}
	}
}

// RunProxyRelay registers with a relay and starts the SOCKS5 front-end using a secure tunnel
func RunProxyRelay(relayAddr string, socksAddr string, secret string) {
	logger.Info("Registering with relay %s", relayAddr)
	rawConn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		logger.Fatalf("Register dial failed: %v", err)
	}
	defer rawConn.Close()
	// send REGISTER header (exactly 8 bytes)
	if _, err := rawConn.Write([]byte("REGISTER")); err != nil {
		logger.Fatalf("Register header send error: %v", err)
	}
	if err := answerRelayChallenge(rawConn, secret); err != nil {
		logger.Fatalf("Relay auth failed: %v", err)
	}
	// secure handshake as server
	secureConn, err := NewSecureServerConn(rawConn, secret)
	if err != nil {
		logger.Fatalf("Secure handshake failed: %v", err)
	}
	// set tunnel connection and start reader for agent replies
	tunnelMu.Lock()
	if tunnelConn != nil {
		tunnelConn.Close()
	}
	tunnelConn = secureConn
	tunnelMu.Unlock()
	// start reading from tunnel and forwarding to SOCKS clients
	go handleTunnelReadsClient(secureConn)
	logger.Info("Tunnel via relay established")
	// start SOCKS5 proxy
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		logger.Fatalf("SOCKS5 listen failed: %v", err)
	}
	logger.Info("SOCKS5 proxy listening on %s", socksAddr)
	for {
		client, err := ln.Accept()
		if err != nil {
			logger.Println("Accept error:", err)
			continue
		}
		go handleSOCKS(client)
	}
}
