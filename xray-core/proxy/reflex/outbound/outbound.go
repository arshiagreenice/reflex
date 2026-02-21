package outbound

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	serverAddr string
	port       uint32
}

func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
	return &Handler{
		serverAddr: config.Address,
		port:       config.Port,
	}, nil
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	// Basic implementation to satisfy interface
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}
