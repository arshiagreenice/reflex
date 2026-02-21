package reflex

type User struct {
    Id     string 
    Policy string 
}

type Account struct {
    Id string
}

type Fallback struct {
    Dest uint32 
}

type InboundConfig struct {
    Clients  []*User 
    Fallback *Fallback 
}

type OutboundConfig struct {
    Address string 
    Port    uint32 
    Id      string 
}
