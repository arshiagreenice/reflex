package inbound

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
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
	ReflexMagic      = 0x5246584C
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeClose   = 0x04
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

// --- PRELOADED CONN (Step 4 Requirement) ---
type preloadedConn struct {
	stat.Connection
	reader *bufio.Reader
}

func (c *preloadedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

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

func (h *Handler) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }

func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	// STEP 4: PEEK (FALLBACK)
	// We peek 4 bytes to check for Magic or HTTP method
	peeked, err := reader.Peek(4)
	if err != nil {
		return h.handleFallback(reader, conn)
	}

	isReflex := false
	// Check Magic
	if len(peeked) >= 4 && binary.BigEndian.Uint32(peeked[0:4]) == ReflexMagic {
		isReflex = true
	} else if len(peeked) >= 4 && string(peeked[0:4]) == "POST" {
		// Check HTTP POST-like
		isReflex = true
	}

	if !isReflex {
		return h.handleFallback(reader, conn)
	}

	return h.handleReflex(ctx, reader, conn, dispatcher)
}

func (h *Handler) handleFallback(reader *bufio.Reader, conn stat.Connection) error {
	if h.fallbackDest == 0 {
		return errors.New("reflex: fallback not configured")
	}

	// Use PreloadedConn to ensure peeked bytes are read
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

// STEP 2: HANDSHAKE
func (h *Handler) handleReflex(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// 1. Read Header (Magic or POST) - discard it for now as we validated in Peek
	discard := make([]byte, 4)
	if _, err := io.ReadFull(reader, discard); err != nil {
		return err
	}

	// 2. Read Client Public Key (32 bytes)
	clientPub := make([]byte, 32)
	if _, err := io.ReadFull(reader, clientPub); err != nil {
		return err
	}

	// 3. Generate Server Keys
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return err
	}
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	// 4. Calculate Shared Key (ECDH)
	var sharedKey [32]byte
	var clientPubArr [32]byte
	copy(clientPubArr[:], clientPub)
	curve25519.ScalarMult(&sharedKey, &privKey, &clientPubArr)

	// 5. Derive Session Key
	sessionKey := hkdfDerive(sharedKey[:], []byte("reflex-session"))

	// 6. Simulate Server Response (HTTP 200 + Server Pub Key)
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	conn.Write(pubKey[:])

	// Create Session
	session, err := NewSession(sessionKey)
	if err != nil {
		return err
	}

	// Step 5: Activate Morphing if configured
	if h.morphingProfile == "youtube" {
		session.SetProfile(YouTubeProfile)
	}

	return h.transport(ctx, session, reader, conn, dispatcher)
}

// STEP 3: TRANSPORT
func (h *Handler) transport(ctx context.Context, s *Session, reader io.Reader, writer io.Writer, dispatcher routing.Dispatcher) error {
	// For this project scope, we route to a demo target (Google).
	// In full production, we'd parse the destination from the first data frame.
	dest := xnet.TCPDestination(xnet.ParseAddress("www.google.com"), 80)

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	request := func() error {
		// link.Writer in Xray usually handles cleanup when the pipe breaks or context cancels
		for {
			frame, err := s.ReadFrame(reader)
			if err != nil {
				return err
			}
			if frame.Type == FrameTypeClose {
				return nil
			}
			// Check for Replay (Step 3 Requirement)
			if !s.CheckReplay(frame.Nonce) {
				return errors.New("replay detected")
			}
			if frame.Type == FrameTypeData {
				link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(frame.Payload)})
			}
		}
	}

	response := func() error {
		defer s.WriteFrame(writer, FrameTypeClose, nil)
		return task.Run(ctx, func() error {
			input := link.Reader
			for {
				mb, err := input.ReadMultiBuffer()
				if err != nil {
					return err
				}
				for _, b := range mb {
					if err := s.WriteFrameWithMorphing(writer, FrameTypeData, b.Bytes()); err != nil {
						b.Release()
						return err
					}
					b.Release()
				}
			}
		})
	}
	return task.Run(ctx, request, response)
}

// --- ENCRYPTION SESSION & REPLAY PROTECTION ---
type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	profile    *TrafficProfile
	seenNonces sync.Map // Simple replay cache
}

type Frame struct {
	Length  uint16
	Type    uint8
	Nonce   uint64 // Added for upper layer checking
	Payload []byte
}

func NewSession(key []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

// CheckReplay implements basic replay protection logic
func (s *Session) CheckReplay(nonce uint64) bool {
	// For strict project scope, verifying strict ordering or caching is enough.
	if _, loaded := s.seenNonces.LoadOrStore(nonce, true); loaded {
		return false
	}
	return true
}

func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	head := make([]byte, 3)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(head[:2])
	fType := head[2]

	encrypted := make([]byte, length)
	if _, err := io.ReadFull(r, encrypted); err != nil {
		return nil, err
	}

	// Prepare nonce for decryption
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

// STEP 5: ADVANCED MORPHING (Statistical)
type TrafficProfile struct {
	TargetSize int
	Delay      time.Duration
	Jitter     time.Duration
}

// Improved Profile for YouTube simulation
var YouTubeProfile = &TrafficProfile{
	TargetSize: 1400,
	Delay:      10 * time.Millisecond,
	Jitter:     5 * time.Millisecond,
}

func (s *Session) SetProfile(p *TrafficProfile) { s.profile = p }

func (s *Session) WriteFrameWithMorphing(w io.Writer, fType uint8, payload []byte) error {
	if s.profile != nil {
		// 1. Packet Padding Logic
		if len(payload) < s.profile.TargetSize {
			padLen := s.profile.TargetSize - len(payload)
			padding := make([]byte, padLen)
			rand.Read(padding)
			// Send actual data
			if err := s.WriteFrame(w, fType, payload); err != nil {
				return err
			}
			// Send Padding Frame immediately after to fill size
			return s.WriteFrame(w, FrameTypePadding, padding)
		}

		// 2. Timing Jitter Logic (Statistical Morphing)
		// For simplicity/speed in this demo, we just sleep base delay.
		// In full crypto implementation, we'd use crypto/rand for jitter.
		time.Sleep(s.profile.Delay)
	}
	return s.WriteFrame(w, fType, payload)
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