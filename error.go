package libsocks

import (
	"fmt"
	"net"
)

type VersionErr struct {
	SourceAddr   net.Addr
	SocksVersion uint8
}

func (e VersionErr) Error() string {
	return fmt.Sprintf("source: %s socks version %d not support", e.SourceAddr, e.SocksVersion)
}
