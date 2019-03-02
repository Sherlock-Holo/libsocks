package libsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/pkg/errors"
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

type VersionErr struct {
	SourceAddr   net.Addr
	SocksVersion uint8
}

func (e VersionErr) Error() string {
	return fmt.Sprintf("socks version %d not support", e.SocksVersion)
}

type Socks struct {
	net.Conn
	*Auth

	Target Address
}

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
		return Socks{}, errors.Wrap(err, "new socks failed")
	}
	return socks, nil
}

func (socks *Socks) init() error {
	var initSuccess bool
	defer func() {
		if !initSuccess {
			socks.Close()
		}
	}()

	verMsg := make([]byte, 2)

	_, err := io.ReadFull(socks, verMsg)
	if err != nil {
		return errors.Wrap(err, "socks read version failed")
	}

	if verMsg[0] != Version {
		return errors.WithStack(VersionErr{socks.LocalAddr(), verMsg[0]})
	}

	methods := make([]byte, verMsg[1])

	_, err = io.ReadFull(socks, methods)
	if err != nil {
		return errors.Wrap(err, "socks read auth methods failed")
	}

	var coincide bool
	for _, auth := range methods {
		if auth == socks.Code {
			coincide = true
			break
		}
	}
	if !coincide {
		return errors.Errorf("auth %d not coincide", socks.Code)
	}

	ok, err := socks.AuthFunc(socks)
	if err != nil {
		return errors.Wrap(err, "socks auth failed")
	}

	if !ok {
		return errors.New("socks auth failed")
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(socks, request); err != nil {
		return errors.Wrap(err, "socks read request failed")
	}

	if request[0] != Version {
		return errors.WithStack(VersionErr{socks.LocalAddr(), request[0]})
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
			return errors.Wrap(err, "socks write cmd not support response failed")
		}
		return errors.New("cmd not support")
	}

	socks.Target.Type = request[3]
	switch socks.Target.Type {
	case IPv4:
		addr := make([]byte, net.IPv4len+2)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return errors.Wrap(err, "socks read ipv4 addr failed")
		}

		socks.Target.IP = net.IP(addr[:net.IPv4len])
		socks.Target.Port = binary.BigEndian.Uint16(addr[net.IPv4len:])

		initSuccess = true
		return nil

	case IPv6:
		addr := make([]byte, net.IPv6len+2)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return errors.Wrap(err, "socks read ipv6 addr failed")
		}

		socks.Target.IP = net.IP(addr[:net.IPv6len])
		socks.Target.Port = binary.BigEndian.Uint16(addr[net.IPv6len:])

		initSuccess = true
		return nil

	case Domain:
		addrLength := make([]byte, 1)
		_, err := socks.Read(addrLength)
		if err != nil {
			socks.Close()
			return err
		}

		addr := make([]byte, addrLength[0]+2)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return errors.Wrap(err, "socks read domain addr failed")
		}

		socks.Target.Host = string(addr[:addrLength[0]])
		socks.Target.Port = binary.BigEndian.Uint16(addr[addrLength[0]:])

		initSuccess = true
		return nil

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
			return errors.Wrap(err, "socks write addr type not support response failed")
		}
		return errors.New("addr type not support")
	}
}

func (socks *Socks) Reply(ip net.IP, port uint16, field ResponseType) error {
	switch field {
	default:
		return errors.Errorf("not support reply filed %d", field)

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

	_, err := socks.Write(reply)
	return errors.Wrap(err, "socks write reply failed")
}
