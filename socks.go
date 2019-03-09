package libsocks

import (
	"encoding/binary"
	"io"
	"net"

	"golang.org/x/xerrors"
)

type ResponseType = uint8

const (
	Success ResponseType = iota
	ServerFailed
	ConnNotAllowed
	NetworkUnreachable
	ConnRefused
	TTLExpired
	CmdNotSupport
	AddrTypeNotSupport
)

const Version = 5

type Socks struct {
	net.Conn
	*Auth

	Target Address
}

// NewSocks NewSocks will auth socks client and read socks request, if error, conn will be closed
func NewSocks(conn net.Conn, auth *Auth) (Socks, error) {
	if auth == nil {
		auth = &NoAuth
	}

	socks := Socks{
		conn,
		auth,
		Address{},
	}

	err := socks.init()
	if err != nil {
		socks.Close()
		return Socks{}, xerrors.Errorf("new socks failed: %w", err)
	}
	return socks, nil
}

func (socks *Socks) init() error {
	verMsg := make([]byte, 2)

	_, err := io.ReadFull(socks, verMsg)
	if err != nil {
		return xerrors.Errorf("socks read version failed: %w", err)
	}

	if verMsg[0] != Version {
		return xerrors.Errorf("socks auth version wrong: %w", VersionErr{socks.RemoteAddr(), verMsg[0]})
	}

	methods := make([]byte, verMsg[1])

	_, err = io.ReadFull(socks, methods)
	if err != nil {
		return xerrors.Errorf("socks read auth methods failed: %w", err)
	}

	var coincide bool
	for _, auth := range methods {
		if auth == socks.Code {
			coincide = true
			break
		}
	}
	if !coincide {
		return xerrors.Errorf("socks auth %d not coincide: %w", socks.Code, err)
	}

	ok, err := socks.AuthFunc(socks)
	if err != nil {
		return xerrors.Errorf("socks auth failed: %w", err)
	}

	if !ok {
		return xerrors.New("socks auth failed")
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(socks, request); err != nil {
		return xerrors.Errorf("socks read request failed: %w", err)
	}

	if request[0] != Version {
		return xerrors.Errorf("socks request version wrong: %w", VersionErr{socks.LocalAddr(), request[0]})
	}

	if request[1] != cmdConnect {
		reply := []byte{Version, CmdNotSupport, 0}
		tcpAddr := socks.LocalAddr().(*net.TCPAddr)

		if len(tcpAddr.IP) == net.IPv6len {
			reply = append(reply, IPv6)
		} else {
			reply = append(reply, IPv4)
		}
		reply = append(reply, tcpAddr.IP...)

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(tcpAddr.Port))
		reply = append(reply, port...)

		_, err = socks.Write(reply)
		if err != nil {
			return xerrors.Errorf("socks write cmd not support response failed: %w", err)
		}
		return xerrors.New("socks cmd not support")
	}

	socks.Target.Type = request[3]
	switch socks.Target.Type {
	case IPv4:
		addr := make([]byte, net.IPv4len+2)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return xerrors.Errorf("socks read ipv4 addr failed: %w", err)
		}

		socks.Target.IP = net.IP(addr[:net.IPv4len])
		socks.Target.Port = binary.BigEndian.Uint16(addr[net.IPv4len:])

	case IPv6:
		addr := make([]byte, net.IPv6len+2)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return xerrors.Errorf("socks read ipv6 addr failed: %w", err)
		}

		socks.Target.IP = net.IP(addr[:net.IPv6len])
		socks.Target.Port = binary.BigEndian.Uint16(addr[net.IPv6len:])

	case Domain:
		addrLength := make([]byte, 1)
		if _, err := socks.Read(addrLength); err != nil {
			return xerrors.Errorf("socks read domain name length failed: %w", err)
		}

		addr := make([]byte, addrLength[0]+2)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return xerrors.Errorf("socks read domain name failed: %w", err)
		}

		socks.Target.Host = string(addr[:addrLength[0]])
		socks.Target.Port = binary.BigEndian.Uint16(addr[addrLength[0]:])

	default:
		reply := []byte{Version, AddrTypeNotSupport, 0}
		tcpAddr := socks.LocalAddr().(*net.TCPAddr)

		if len(tcpAddr.IP) == net.IPv6len {
			reply = append(reply, IPv6)
		} else {
			reply = append(reply, IPv4)
		}
		reply = append(reply, tcpAddr.IP...)

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(tcpAddr.Port))
		reply = append(reply, port...)

		_, err = socks.Write(reply)
		if err != nil {
			return xerrors.Errorf("socks write addr type not support response failed: %w", err)
		}
		return xerrors.New("socks addr type not support")
	}

	return nil
}

func (socks *Socks) Reply(ip net.IP, port uint16, field ResponseType) error {
	switch field {
	default:
		return xerrors.Errorf("not support reply filed %d", field)

	case Success, ServerFailed, ConnNotAllowed, NetworkUnreachable, ConnRefused, TTLExpired, CmdNotSupport, AddrTypeNotSupport:
	}

	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)

	reply := []byte{Version, field, 0}
	if len(ip) == net.IPv4len {
		reply = append(reply, IPv4)
	} else {
		reply = append(reply, IPv6)
	}
	reply = append(reply, ip...)
	reply = append(reply, pb...)

	if _, err := socks.Write(reply); err != nil {
		return xerrors.Errorf("socks write reply failed: %w", err)
	}

	return nil
}
