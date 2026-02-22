package inbound

import (
"bufio"
"context"
"crypto/cipher"
"crypto/rand"
"crypto/sha256"
"encoding/binary"
"errors"
"io"
"net"
"time"

"github.com/xtls/xray-core/common"
"github.com/xtls/xray-core/common/buf"
xnet "github.com/xtls/xray-core/common/net"
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
FrameTypeTiming  = 0x03
FrameTypeClose   = 0x04
PADDING_CTRL     = FrameTypePadding
TIMING_CTRL      = FrameTypeTiming
)

type Session struct {
key        []byte
aead       cipher.AEAD
readNonce  uint64
writeNonce uint64
profile    *TrafficProfile
}

func init() {
common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
return New(ctx, config.(*reflex.InboundConfig))
}))
}

type FallbackConfig struct {
Dest uint32
}

type Handler struct {
clients  []*reflex.User
fallback *FallbackConfig
}

func (h *Handler) Network() []xnet.Network {
return []xnet.Network{xnet.Network_TCP}
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
handler := &Handler{
clients: config.Clients,
}
if config.Fallback != nil {
handler.fallback = &FallbackConfig{Dest: config.Fallback.Dest}
}
return handler, nil
}

func (h *Handler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
reader := bufio.NewReader(conn)
peeked, err := reader.Peek(4)
if err != nil {
return h.handleFallback(ctx, reader, conn)
}

magic := binary.BigEndian.Uint32(peeked[0:4])
if magic == ReflexMagic {
return h.handleReflexMagic(reader, conn, dispatcher, ctx)
}

if h.isHTTPPostLike(peeked) {
return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
}

return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) isHTTPPostLike(data []byte) bool {
if len(data) >= 4 && string(data[0:4]) == "POST" {
return true
}
return false
}

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn stat.Connection) error {
if h.fallback == nil {
return errors.New("no fallback configured")
}
targetAddr := net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(h.fallback.Dest)}
target, err := net.DialTCP("tcp", nil, &targetAddr)
if err != nil {
return err
}
defer target.Close()

wrappedConn := &preloadedConn{Reader: reader, Connection: conn}

errc := make(chan error, 2)
go func() {
_, err := io.Copy(target, wrappedConn)
errc <- err
}()
go func() {
_, err := io.Copy(wrappedConn, target)
errc <- err
}()
<-errc
return nil
}

type preloadedConn struct {
*bufio.Reader
stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error) {
return pc.Reader.Read(b)
}
func (pc *preloadedConn) Write(b []byte) (int, error) {
return pc.Connection.Write(b)
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
magic := make([]byte, 4)
if _, err := io.ReadFull(reader, magic); err != nil {
return err
}

pubKey := make([]byte, 32)
if _, err := io.ReadFull(reader, pubKey); err != nil {
return err
}
uuidBytes := make([]byte, 16)
if _, err := io.ReadFull(reader, uuidBytes); err != nil {
return err
}

pad := make([]byte, 32)
io.ReadFull(reader, pad)

return h.processHandshake(reader, conn, dispatcher, ctx, pubKey, uuidBytes)
}

func (h *Handler) handleReflexHTTP(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context, clientPubKey []byte, uuidBytes []byte) error {
var privateKey [32]byte
var publicKey [32]byte
rand.Read(privateKey[:])
curve25519.ScalarBaseMult(&publicKey, &privateKey)

var peerPubKey [32]byte
copy(peerPubKey[:], clientPubKey)

sharedKey, _ := curve25519.X25519(privateKey[:], peerPubKey[:])

hkdfReader := hkdf.New(sha256.New, sharedKey, []byte("reflex-session"), nil)
sessionKey := make([]byte, 32)
hkdfReader.Read(sessionKey)

authenticated := false
var policy string
for _, c := range h.clients {
if c.Id != "" {
authenticated = true
policy = c.Policy
break
}
}
if !authenticated {
return errors.New("unauthorized UUID")
}

resp := append([]byte("HTTP/1.1 200 OK\r\n\r\n"), publicKey[:]...)
if _, err := conn.Write(resp); err != nil {
return err
}

return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, policy)
}

func (h *Handler) handleSession(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, sessionKey []byte, policy string) error {
aead, err := chacha20poly1305.New(sessionKey)
if err != nil {
return err
}
session := &Session{
key:     sessionKey,
aead:    aead,
profile: GetProfile(policy),
}

dest := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(80))
link, err := dispatcher.Dispatch(ctx, dest)

if err == nil && link != nil {
go func() {
defer common.Close(link.Writer)
for {
mb, err := link.Reader.ReadMultiBuffer()
if err != nil {
return
}
for _, b := range mb {
session.WriteFrame(conn, FrameTypeData, b.Bytes())
b.Release()
}
}
}()
}

for {
header := make([]byte, 3)
if _, err := io.ReadFull(reader, header); err != nil {
return err
}
length := binary.BigEndian.Uint16(header[0:2])
frameType := header[2]

encryptedPayload := make([]byte, length)
if length > 0 {
if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
return err
}
}

var payload []byte
if length > 0 {
nonce := make([]byte, 12)
binary.BigEndian.PutUint64(nonce[4:], session.readNonce)
session.readNonce++
payload, err = session.aead.Open(nil, nonce, encryptedPayload, nil)
if err != nil {
return err
}
}

switch frameType {
case FrameTypeData:
if link != nil && link.Writer != nil && len(payload) > 0 {
buffer := buf.FromBytes(payload)
link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer})
}
case FrameTypePadding:
// ignore
case FrameTypeTiming:
// ignore
case FrameTypeClose:
return nil
default:
return nil
}
}
}

func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
var encrypted []byte
if len(data) > 0 {
nonce := make([]byte, 12)
binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
s.writeNonce++
encrypted = s.aead.Seal(nil, nonce, data, nil)
}

header := make([]byte, 3)
binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
header[2] = frameType

if _, err := writer.Write(header); err != nil {
return err
}
if len(encrypted) > 0 {
if _, err := writer.Write(encrypted); err != nil {
return err
}
}
return nil
}

type TrafficProfile struct { Name string }
func GetProfile(name string) *TrafficProfile { return &TrafficProfile{Name: name} }
func (p *TrafficProfile) GetPacketSize() int { return 1000 }
func (p *TrafficProfile) GetDelay() time.Duration { return 10 * time.Millisecond }
func (s *Session) AddPadding(data []byte, targetSize int) []byte {
if len(data) >= targetSize { return data[:targetSize] }
padding := make([]byte, targetSize-len(data))
rand.Read(padding)
return append(data, padding...)
}
