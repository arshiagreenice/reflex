package conf

import (
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexAccount struct {
	Id   string `json:"id"`
	Flow string `json:"flow"`
}

func (a *ReflexAccount) Build() *reflex.Account {
	return &reflex.Account{
		Id:   a.Id,
		Flow: a.Flow,
	}
}

type ReflexFallback struct {
	Dest uint32 `json:"dest"`
	Xver string `json:"xver"`
}

type ReflexInboundConfig struct {
	Clients         []*ReflexAccount `json:"clients"`
	Fallback        *ReflexFallback  `json:"fallback"`
	MorphingProfile string           `json:"morphing"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := &reflex.InboundConfig{
		MorphingProfile: c.MorphingProfile,
	}

	if c.Clients != nil {
		for _, client := range c.Clients {
			config.Clients = append(config.Clients, client.Build())
		}
	}

	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
			Xver: c.Fallback.Xver,
		}
	}

	return config, nil
}

type ReflexOutboundConfig struct {
	Address string           `json:"address"`
	Port    uint32           `json:"port"`
	Clients []*ReflexAccount `json:"clients"`
}

func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	config := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
	}
	for _, client := range c.Clients {
		config.Clients = append(config.Clients, client.Build())
	}
	return config, nil
}
