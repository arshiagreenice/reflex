package outbound

import (
"context"
"github.com/xtls/xray-core/common"
"github.com/xtls/xray-core/proxy"
"github.com/xtls/xray-core/proxy/reflex"
"github.com/xtls/xray-core/transport"
"github.com/xtls/xray-core/transport/internet"
)

func init() {
common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
return New(ctx, config.(*reflex.OutboundConfig))
}))
}

// Handler handles outbound
type Handler struct{ config *reflex.OutboundConfig }

// Process processes traffic
func (h *Handler) Process(ctx context.Context, link *transport.Link, d internet.Dialer) error {
_ = ctx
_ = d
_ = link.Reader
_ = link.Writer
return nil
}

// New creates outbound
func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
_ = ctx
return &Handler{config: config}, nil
}
