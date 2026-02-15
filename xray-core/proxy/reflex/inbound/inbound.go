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
	peeked, err := reader.Peek(4)
	if err != nil {
		return h.handleFallback(reader, conn)
	}

	isReflex := false
	if len(peeked) >= 4 && binary.BigEndian.Uint32(peeked[0:4]) == ReflexMagic {
		isReflex = true
	} else if len(peeked) >= 4 && string(peeked[0:4]) == "POST" {
		isReflex = true
	}

	if !isReflex {
		return h.handleFallback(reader, conn)
	}

	return h.handleReflex(ctx, reader, conn, dispatcher)
}

func (h *Handler) handleFallback(reader io.Reader, conn stat.Connection) error {
	if h.fallbackDest == 0 {
		return errors.New("reflex: fallback not configured")
	}
	destAddr := fmt.Sprintf("127.0.0.1:%d", h.fallbackDest)
	remote, err := net.Dial("tcp", destAddr)
	if err != nil {
		return err
	}
	defer remote.Close()
	
	go io.Copy(remote, reader)
	io.Copy(conn, remote)
	return nil
}

// STEP 2: HANDSHAKE
func (h *Handler) handleReflex(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	discard := make([]byte, 4)
	io.ReadFull(reader, discard)

	clientPub := make([]byte, 32)
	io.ReadFull(reader, clientPub)

	var privKey [32]byte
	rand.Read(privKey[:])
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	sharedKey := make([]byte, 32) 
	sessionKey := hkdfDerive(sharedKey, []byte("reflex-session"))

	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	conn.Write(pubKey[:])

	session, _ := NewSession(sessionKey)
	if h.morphingProfile == "youtube" {
		session.SetProfile(YouTubeProfile)
	}

	return h.transport(ctx, session, reader, conn, dispatcher)
}

// STEP 3: TRANSPORT
func (h *Handler) transport(ctx context.Context, s *Session, reader io.Reader, writer io.Writer, dispatcher routing.Dispatcher) error {
	dest := xnet.TCPDestination(xnet.ParseAddress("www.google.com"), 80)
	
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	request := func() error {
		// Removed Close() as it's not needed/supported for buf.Writer
		for {
			frame, err := s.ReadFrame(reader)
			if err != nil { return err }
			if frame.Type == FrameTypeClose { return nil }
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
				if err != nil { return err }
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

// --- ENCRYPTION SESSION ---
type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	profile    *TrafficProfile
}
type Frame struct {
	Length uint16
	Type   uint8
	Payload []byte
}

func NewSession(key []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil { return nil, err }
	return &Session{aead: aead}, nil
}

func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	head := make([]byte, 3)
	if _, err := io.ReadFull(r, head); err != nil { return nil, err }
	length := binary.BigEndian.Uint16(head[:2])
	fType := head[2]

	encrypted := make([]byte, length)
	if _, err := io.ReadFull(r, encrypted); err != nil { return nil, err }

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++

	payload, err := s.aead.Open(nil, nonce, encrypted, nil)
	if err != nil { return nil, err }
	return &Frame{Length: length, Type: fType, Payload: payload}, nil
}

func (s *Session) WriteFrame(w io.Writer, fType uint8, payload []byte) error {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, payload, nil)
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[:2], uint16(len(encrypted)))
	header[2] = fType

	w.Write(header)
	_, err := w.Write(encrypted)
	return err
}

// STEP 5: MORPHING
type TrafficProfile struct { TargetSize int; Delay time.Duration }
var YouTubeProfile = &TrafficProfile{TargetSize: 1400, Delay: 10 * time.Millisecond}

func (s *Session) SetProfile(p *TrafficProfile) { s.profile = p }

func (s *Session) WriteFrameWithMorphing(w io.Writer, fType uint8, payload []byte) error {
	if s.profile != nil {
		if len(payload) < s.profile.TargetSize {
			padLen := s.profile.TargetSize - len(payload)
			padding := make([]byte, padLen)
			rand.Read(padding)
			s.WriteFrame(w, fType, payload)
			return s.WriteFrame(w, FrameTypePadding, padding)
		}
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