package inbound_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/proxy/reflex/inbound"
	"github.com/xtls/xray-core/common/protocol"
)

func TestReflexStructure(t *testing.T) {
	// 1. Test Config Loading
	config := &reflex.InboundConfig{
		Clients: []*reflex.Account{
			{Id: "ad806487-2d26-4636-98b6-ab85cc8521f7"},
		},
		MorphingProfile: "youtube",
	}

	// 2. Test Handler Creation
	ctx := context.Background()
	handler, err := inbound.New(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	if len(handler.Network()) == 0 {
		t.Error("Handler network should not be empty")
	}
}

func TestMorphingProfile(t *testing.T) {
	// 3. Test Morphing Logic (Bonus Feature verification)
	// We verify that the profile constants are set correctly for YouTube
	if inbound.YouTubeProfile.TargetSize != 1400 {
		t.Errorf("YouTube profile target size should be 1400, got %d", inbound.YouTubeProfile.TargetSize)
	}
	if inbound.YouTubeProfile.Delay != 10*time.Millisecond {
		t.Errorf("YouTube profile delay should be 10ms")
	}
}