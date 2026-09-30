package redirect

const ABIVersion = 1

type FlowKey struct {
	Version      uint32
	Family       uint16
	Protocol     uint8
	Reserved     uint8
	Client       [16]byte
	Listener     [16]byte
	ClientPort   uint16
	ListenerPort uint16
	Reserved2    uint32
}
type FlowValue struct {
	Version     uint32
	Family      uint16
	Port        uint16
	Destination [16]byte
	UID         uint32
	TGID        uint32
	Cookie      uint64
	CreatedNS   uint64
}
type Policy struct {
	Version      uint32
	Enabled      uint32
	AllNonBypass uint32
	IPv6         uint32
	Port         uint16
	Reserved     uint16
	IPv4         [4]byte
	HeartbeatNS  uint64
	LeaseNS      uint64
}
type Prefix struct {
	Bits    uint32
	Address [16]byte
}
