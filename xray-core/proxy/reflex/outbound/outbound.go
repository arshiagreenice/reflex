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
type Handler struct { config *reflex.OutboundConfig }
func (h *Handler) Process(ctx context.Context, link *transport.Link, d internet.Dialer) error {
_ = link.Reader
_ = link.Writer
return nil
}
func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.Outbound, error) {
return &Handler{config: config}, nil
}
