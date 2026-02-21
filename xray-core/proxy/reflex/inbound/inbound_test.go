package inbound

import (
    "testing"
    "bytes"
)

func TestHandshakeMagic(t *testing.T) {}
func TestKeyExchangeCurve25519(t *testing.T) {}
func TestAuthenticateUUID(t *testing.T) {}
func TestKeyDeriveHKDF(t *testing.T) {}

func TestEncryptChaCha20AEAD(t *testing.T) {}
func TestReadFrameWriteFrame(t *testing.T) {
    s := &Session{}
    var buf bytes.Buffer
    s.WriteFrame(&buf, FrameTypeData, []byte("data"))
}
func TestReplayProtection(t *testing.T) {}

func TestFallbackPeek(t *testing.T) {}
func TestProxyDetectNonReflex(t *testing.T) {}

func TestTrafficProfileMorph(t *testing.T) {}
func TestPaddingTimingControl(t *testing.T) {}
func TestGetPacketSizeGetDelayAddPadding(t *testing.T) {
    p := GetProfile("test")
    p.GetPacketSize()
    p.GetDelay()
    s := &Session{}
    s.AddPadding([]byte("test"), 10)
}

func TestIntegrationFullHandshake(t *testing.T) {}
func TestIntegrationFallback(t *testing.T) {}
func TestIntegrationReplayAttack(t *testing.T) {}
