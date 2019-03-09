package libsocks

import (
	"net"

	"golang.org/x/xerrors"
)

type Auth struct {
	Code     uint8
	AuthFunc func(conn net.Conn) (bool, error)
}

var (
	NoAuth = Auth{0, func(conn net.Conn) (bool, error) {
		_, err := conn.Write([]byte{Version, 0})
		if err != nil {
			return false, xerrors.Errorf("no-password auth failed: %w", err)
		}

		return true, nil
	}}
)
