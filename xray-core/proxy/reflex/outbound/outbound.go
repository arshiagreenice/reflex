package outbound

import (
    "context"
    "io"

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

type Handler struct {
    config *reflex.OutboundConfig
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, d internet.Dialer) error {
    conn, err := d.Dial(ctx, internet.DialerOptions{})
    if err != nil {
        return err
    }
    defer conn.Close()

    go io.Copy(conn, link.Reader)
    io.Copy(link.Writer, conn)
    return nil
}

func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.OutboundHandler, error) {
    return &Handler{config: config}, nil
}
