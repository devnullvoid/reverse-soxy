package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"time"
)

var errAuthFailed = errors.New("authentication failed")

const handshakeTimeout = 2 * time.Minute
const handshakeChallengeSize = sha256.Size

func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

type secureConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (s *secureConn) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s *secureConn) Write(p []byte) (int, error) {
	return s.w.Write(p)
}

// NewSecureClientConn performs HMAC auth and AES-CTR encryption on a client-side tunnel connection
func NewSecureClientConn(conn net.Conn, secret string) (net.Conn, error) {
	key := deriveKey(secret)
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})
	// read server challenge and respond with HMAC to prevent replay
	challenge := make([]byte, handshakeChallengeSize)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(challenge)
	if _, err := conn.Write(mac.Sum(nil)); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// generate separate IVs for each direction
	ivEnc := make([]byte, aes.BlockSize)
	ivDec := make([]byte, aes.BlockSize)
	if _, err := rand.Read(ivEnc); err != nil {
		return nil, err
	}
	if _, err := rand.Read(ivDec); err != nil {
		return nil, err
	}
	// send IVs: client->server encrypt IV then decrypt IV
	if _, err := conn.Write(ivEnc); err != nil {
		return nil, err
	}
	if _, err := conn.Write(ivDec); err != nil {
		return nil, err
	}
	// create independent CTR streams
	enc := cipher.NewCTR(block, ivEnc)
	dec := cipher.NewCTR(block, ivDec)
	return &secureConn{Conn: conn, r: cipher.StreamReader{S: dec, R: conn}, w: cipher.StreamWriter{S: enc, W: conn}}, nil
}

// NewSecureServerConn performs HMAC auth and AES-CTR encryption on a server-side tunnel connection
func NewSecureServerConn(conn net.Conn, secret string) (net.Conn, error) {
	key := deriveKey(secret)
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})
	// send challenge to defend against replayed handshakes
	challenge := make([]byte, handshakeChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	if _, err := conn.Write(challenge); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(challenge)
	recvMac := make([]byte, mac.Size())
	if _, err := io.ReadFull(conn, recvMac); err != nil {
		return nil, err
	}
	if !hmac.Equal(recvMac, mac.Sum(nil)) {
		return nil, errAuthFailed
	}
	// read IVs from client
	ivEnc := make([]byte, aes.BlockSize)
	ivDec := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(conn, ivEnc); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, ivDec); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// create independent CTR streams: decrypt client->server using ivEnc, encrypt server->client using ivDec
	dec := cipher.NewCTR(block, ivEnc)
	enc := cipher.NewCTR(block, ivDec)
	// disable Nagle on underlying TCP
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	return &secureConn{Conn: conn, r: cipher.StreamReader{S: dec, R: conn}, w: cipher.StreamWriter{S: enc, W: conn}}, nil
}
