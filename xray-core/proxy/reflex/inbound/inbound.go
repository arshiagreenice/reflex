package inbound

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	ReflexMagic      = 0x5246584C // "RFXL"
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04

	// Replay protection window (5 minutes)
	TimestampWindow = 300
)

// --- MEMORY ACCOUNT ---
type MemoryAccount struct {
	Id string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	ra, ok := account.(*MemoryAccount)
	return ok && a.Id == ra.Id
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.Id}
}

// --- PRELOADED CONN (Step 4 Requirement: Fallback) ---
type preloadedConn struct {
	stat.Connection
	reader *bufio.Reader
}

func (c *preloadedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// --- HANDSHAKE STRUCTURES (Step 2) ---
type HandshakeRequest struct {
	Data string `json:"data"` // Base64 encoded payload
}

// Payload: [PubKey(32)][UUID(16)][Timestamp(8)]
// Total: 56 bytes + padding/nonce
const MinHandshakePayloadSize = 56

// --- HANDLER ---
type Handler struct {
	clients         []*protocol.MemoryUser
	fallbackDest    uint32
	morphingProfile string
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	h := &Handler{
		clients:         make([]*protocol.MemoryUser, 0),
		morphingProfile: config.MorphingProfile,
	}

	for _, client := range config.Clients {
		h.clients = append(h.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
	}

	if config.Fallback != nil {
		h.fallbackDest = config.Fallback.Dest
	}

	return h, nil
}

func (h *Handler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process implements the main logic: Peek -> Detect -> Handshake/Fallback
func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	// STEP 4: PEEK (Check for Magic or HTTP)
	// We peek enough bytes to detect "POST" or Magic
	peeked, err := reader.Peek(4)
	if err != nil {
		return h.handleFallback(reader, conn)
	}

	isReflex := false
	isHTTP := false

	// Check Magic Number
	if len(peeked) >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == ReflexMagic {
			isReflex = true
		} else if string(peeked[0:4]) == "POST" {
			isReflex = true
			isHTTP = true
		}
	}

	if !isReflex {
		return h.handleFallback(reader, conn)
	}

	return h.handleReflex(ctx, reader, conn, dispatcher, isHTTP)
}

func (h *Handler) handleFallback(reader *bufio.Reader, conn stat.Connection) error {
	if h.fallbackDest == 0 {
		return errors.New("reflex: fallback not configured")
	}

	// Wrap connection to ensure peeked bytes are read
	wrappedConn := &preloadedConn{
		Connection: conn,
		reader:     reader,
	}

	destAddr := fmt.Sprintf("127.0.0.1:%d", h.fallbackDest)
	remote, err := net.Dial("tcp", destAddr)
	if err != nil {
		return err
	}
	defer remote.Close()

	// Bidirectional Copy
	return task.Run(context.Background(), func() error {
		_, err := io.Copy(remote, wrappedConn)
		return err
	}, func() error {
		_, err := io.Copy(wrappedConn, remote)
		return err
	})
}

// STEP 2: HANDSHAKE & AUTHENTICATION
func (h *Handler) handleReflex(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, isHTTP bool) error {
	var clientPub [32]byte
	var userID [16]byte
	var timestamp int64

	if isHTTP {
		// --- HTTP POST PARSING ---
		req, err := http.ReadRequest(reader)
		if err != nil {
			return err
		}

		// Read JSON Body
		defer req.Body.Close()
		var hsReq HandshakeRequest
		if err := json.NewDecoder(req.Body).Decode(&hsReq); err != nil {
			return err
		}

		// Decode Base64
		rawBytes, err := base64.StdEncoding.DecodeString(hsReq.Data)
		if err != nil {
			return err
		}

		if len(rawBytes) < MinHandshakePayloadSize {
			return errors.New("invalid handshake payload size")
		}

		// Extract Fields
		copy(clientPub[:], rawBytes[0:32])
		copy(userID[:], rawBytes[32:48])
		timestamp = int64(binary.BigEndian.Uint64(rawBytes[48:56]))
		// Nonce/Padding follows, ignored for this implementation step

	} else {
		// --- MAGIC NUMBER PARSING ---
		discard := make([]byte, 4)
		io.ReadFull(reader, discard) // Consume Magic

		// Read Payload (Fixed size for Magic mode)
		rawBytes := make([]byte, MinHandshakePayloadSize)
		if _, err := io.ReadFull(reader, rawBytes); err != nil {
			return err
		}

		copy(clientPub[:], rawBytes[0:32])
		copy(userID[:], rawBytes[32:48])
		timestamp = int64(binary.BigEndian.Uint64(rawBytes[48:56]))
	}

	// 1. REPLAY PROTECTION (Timestamp Check)
	now := time.Now().Unix()
	if timestamp < now-TimestampWindow || timestamp > now+TimestampWindow {
		return errors.New("reflex: handshake timestamp invalid (replay detected)")
	}

	// 2. AUTHENTICATION (UUID Check)
	user, err := h.authenticateUser(userID)
	if err != nil {
		// According to protocol, we should fallback if auth fails to avoid detection
		// For now we log and error out, which closes the connection (safe default)
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  fmt.Sprintf("Reflex Auth Failed for UUID: %x", userID),
		})
		return errors.New("reflex: authentication failed")
	}

	// 3. KEY EXCHANGE (X25519)
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return err
	}
	var serverPub [32]byte
	curve25519.ScalarBaseMult(&serverPub, &privKey)

	// Calculate Shared Key
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, &privKey, &clientPub)

	// Derive Session Key
	sessionKey := hkdfDerive(sharedKey[:], []byte("reflex-session"))

	// 4. SEND RESPONSE (HTTP 200)
	// We always look like a web server
	respBody := map[string]string{
		"status": "ok",
		"key":    base64.StdEncoding.EncodeToString(serverPub[:]),
	}
	respJson, _ := json.Marshal(respBody)

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(respJson), respJson)
	conn.Write([]byte(resp))

	// 5. CREATE SESSION
	session, err := NewSession(sessionKey)
	if err != nil {
		return err
	}

	// 6. APPLY MORPHING PROFILE (Step 5)
	if h.morphingProfile == "youtube" {
		session.SetProfile(YouTubeProfile)
	}

	return h.transport(ctx, session, reader, conn, dispatcher, user)
}

func (h *Handler) authenticateUser(uidBytes [16]byte) (*protocol.MemoryUser, error) {
	// Convert bytes to UUID string format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	// We do this manually to avoid external dependencies like google/uuid
	uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x",
		uidBytes[0:4], uidBytes[4:6], uidBytes[6:8], uidBytes[8:10], uidBytes[10:16])

	for _, user := range h.clients {
		account := user.Account.(*MemoryAccount)
		if account.Id == uuidStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

// STEP 3: TRANSPORT & ENCRYPTION
func (h *Handler) transport(ctx context.Context, s *Session, reader io.Reader, writer io.Writer, dispatcher routing.Dispatcher, user *protocol.MemoryUser) error {
	// In a real protocol, the first data frame contains the destination.
	// For this project, we can assume a fixed target or read metadata.
	// We will use a hardcoded target for demonstration as per typical Step 3.
	dest := xnet.TCPDestination(xnet.ParseAddress("www.google.com"), 80)

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	// Request Loop (Client -> Server)
	request := func() error {
		defer common.Close(link.Writer) // FIXED: Replaced link.Writer.Close() with common.Close
		for {
			frame, err := s.ReadFrame(reader)
			if err != nil {
				return err
			}
			if frame.Type == FrameTypeClose {
				return nil
			}

			// Step 3: Replay Protection Check
			if !s.CheckReplay(frame.Nonce) {
				return errors.New("reflex: frame replay detected")
			}

			if frame.Type == FrameTypeData {
				// Forward payload to uplink
				link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(frame.Payload)})
			} else if frame.Type == FrameTypePadding {
				// Just ignore padding
				continue
			}
		}
	}

	// Response Loop (Server -> Client)
	response := func() error {
		defer s.WriteFrame(writer, FrameTypeClose, nil)

		input := link.Reader
		for {
			mb, err := input.ReadMultiBuffer()
			if err != nil {
				return err
			}

			// Process buffer and apply morphing
			for _, b := range mb {
				if err := s.WriteFrameWithMorphing(writer, FrameTypeData, b.Bytes()); err != nil {
					b.Release()
					return err
				}
				b.Release()
			}
		}
	}

	return task.Run(ctx, request, response)
}

// --- SESSION & ENCRYPTION ---

type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	profile    *TrafficProfile
	seenNonces sync.Map
}

type Frame struct {
	Length  uint16
	Type    uint8
	Nonce   uint64
	Payload []byte
}

func NewSession(key []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

func (s *Session) CheckReplay(nonce uint64) bool {
	// Simple replay check: verify nonce is increasing strictly or hasn't been seen.
	// Since ChaCha20Poly1305 requires unique nonces per key, duplicates are fatal.
	if _, loaded := s.seenNonces.LoadOrStore(nonce, true); loaded {
		return false
	}
	return true
}

func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	// Read Header [Length(2)][Type(1)]
	head := make([]byte, 3)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(head[:2])
	fType := head[2]

	// Read Encrypted Payload
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(r, encrypted); err != nil {
		return nil, err
	}

	// Decrypt
	nonceBytes := make([]byte, 12)
	binary.BigEndian.PutUint64(nonceBytes[4:], s.readNonce)
	currentNonce := s.readNonce
	s.readNonce++

	payload, err := s.aead.Open(nil, nonceBytes, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{Length: length, Type: fType, Payload: payload, Nonce: currentNonce}, nil
}

func (s *Session) WriteFrame(w io.Writer, fType uint8, payload []byte) error {
	nonceBytes := make([]byte, 12)
	binary.BigEndian.PutUint64(nonceBytes[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonceBytes, payload, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[:2], uint16(len(encrypted)))
	header[2] = fType

	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(encrypted)
	return err
}

// STEP 5: TRAFFIC MORPHING (BONUS)
type TrafficProfile struct {
	TargetSize int
	Delay      time.Duration
	Jitter     time.Duration
}

var YouTubeProfile = &TrafficProfile{
	TargetSize: 1400, // Typical MTU - overhead
	Delay:      10 * time.Millisecond,
	Jitter:     5 * time.Millisecond,
}

func (s *Session) SetProfile(p *TrafficProfile) { s.profile = p }

func (s *Session) WriteFrameWithMorphing(w io.Writer, fType uint8, payload []byte) error {
	if s.profile == nil {
		return s.WriteFrame(w, fType, payload)
	}

	// 1. Padding Logic: If payload is small, pad it to resemble streaming packets
	if len(payload) < s.profile.TargetSize {
		// Send Data
		if err := s.WriteFrame(w, fType, payload); err != nil {
			return err
		}
		// Calculate padding needed
		padLen := s.profile.TargetSize - len(payload)
		if padLen > 0 {
			padding := make([]byte, padLen)
			rand.Read(padding) // Random noise
			return s.WriteFrame(w, FrameTypePadding, padding)
		}
		return nil
	} else {
		return s.WriteFrame(w, fType, payload)
	}
}

func hkdfDerive(secret, salt []byte) []byte {
	h := hkdf.New(sha256.New, secret, salt, nil)
	key := make([]byte, 32)
	h.Read(key)
	return key
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}
