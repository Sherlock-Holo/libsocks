package libsocks

import (
	"net"

	"golang.org/x/xerrors"
)

type Authentication interface {
	AuthFunc(conn net.Conn) (bool, error)
	Code() uint8
}

type NoAuth struct{}

func (na NoAuth) Code() uint8 {
	return 0
}

func (na NoAuth) AuthFunc(conn net.Conn) (bool, error) {
	_, err := conn.Write([]byte{Version, 0})
	if err != nil {
		return false, xerrors.Errorf("no-password auth failed: %w", err)
	}

	return true, nil
}
