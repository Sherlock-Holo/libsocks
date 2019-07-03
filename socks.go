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

type SocksServer struct {
	net.Conn
	Auth Authentication

	Target Address
}

// NewSocks NewSocks will auth socks client and read socks request, if error, conn will be closed
func NewSocks(conn net.Conn, auth Authentication) (*SocksServer, error) {
	if auth == nil {
		auth = NoAuth{}
	}

	socksServer := &SocksServer{
		conn,
		auth,
		Address{},
	}

	err := socksServer.init()
	if err != nil {
		_ = socksServer.Close()
		return nil, xerrors.Errorf("new socksServer failed: %w", err)
	}
	return socksServer, nil
}

func (server *SocksServer) init() error {
	verMsg := make([]byte, 2)

	_, err := io.ReadFull(server, verMsg)
	if err != nil {
		return xerrors.Errorf("socks read version failed: %w", err)
	}

	if verMsg[0] != Version {
		return xerrors.Errorf("socks auth version wrong: %w", VersionErr{server.RemoteAddr(), verMsg[0]})
	}

	methods := make([]byte, verMsg[1])

	_, err = io.ReadFull(server, methods)
	if err != nil {
		return xerrors.Errorf("socks read auth methods failed: %w", err)
	}

	var coincide bool
	for _, auth := range methods {
		if auth == server.Auth.Code() {
			coincide = true
			break
		}
	}
	if !coincide {
		return xerrors.Errorf("socks auth %d not coincide: %w", server.Auth.Code(), err)
	}

	ok, err := server.Auth.AuthFunc(server)
	if err != nil {
		return xerrors.Errorf("socks auth failed: %w", err)
	}

	if !ok {
		return xerrors.New("socks auth failed")
	}

	// [version 1 byte | cmd 1 byte | rsv 1 byte | addr_type 1 byte]
	request := make([]byte, 4)
	if _, err := io.ReadFull(server, request); err != nil {
		return xerrors.Errorf("socks read request failed: %w", err)
	}

	if request[0] != Version {
		return xerrors.Errorf("socks request version wrong: %w", VersionErr{server.LocalAddr(), request[0]})
	}

	// only support cmd connect
	if request[1] != cmdConnect {
		reply := []byte{Version, CmdNotSupport, 0}
		tcpAddr := server.LocalAddr().(*net.TCPAddr)

		if len(tcpAddr.IP) == net.IPv6len {
			reply = append(reply, TypeIPv6)
		} else {
			reply = append(reply, TypeIPv4)
		}
		reply = append(reply, tcpAddr.IP...)

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(tcpAddr.Port))
		reply = append(reply, port...)

		_, err = server.Write(reply)
		if err != nil {
			return xerrors.Errorf("socks write cmd not support response failed: %w", err)
		}
		return xerrors.New("socks cmd not support")
	}

	server.Target.Type = request[3]
	switch server.Target.Type {
	case TypeIPv4:
		addr := make([]byte, net.IPv4len+2)

		if _, err := io.ReadFull(server, addr); err != nil {
			return xerrors.Errorf("socks read ipv4 addr failed: %w", err)
		}

		server.Target.IP = net.IP(addr[:net.IPv4len])
		server.Target.Port = binary.BigEndian.Uint16(addr[net.IPv4len:])

	case TypeIPv6:
		addr := make([]byte, net.IPv6len+2)

		if _, err := io.ReadFull(server, addr); err != nil {
			return xerrors.Errorf("socks read ipv6 addr failed: %w", err)
		}

		server.Target.IP = net.IP(addr[:net.IPv6len])
		server.Target.Port = binary.BigEndian.Uint16(addr[net.IPv6len:])

	case TypeDomain:
		addrLengthByte := make([]byte, 1)
		if _, err := server.Read(addrLengthByte); err != nil {
			return xerrors.Errorf("socks read domain name length failed: %w", err)
		}

		addrLength := int(addrLengthByte[0])

		addr := make([]byte, addrLength+2)

		if _, err := io.ReadFull(server, addr); err != nil {
			return xerrors.Errorf("socks read domain name failed: %w", err)
		}

		server.Target.Host = string(addr[:addrLength])
		server.Target.Port = binary.BigEndian.Uint16(addr[addrLength:])

	default:
		reply := []byte{Version, AddrTypeNotSupport, 0}
		tcpAddr := server.LocalAddr().(*net.TCPAddr)

		if len(tcpAddr.IP) == net.IPv6len {
			reply = append(reply, TypeIPv6)
		} else {
			reply = append(reply, TypeIPv4)
			tcpAddr.IP = tcpAddr.IP.To4()
		}
		reply = append(reply, tcpAddr.IP...)

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(tcpAddr.Port))
		reply = append(reply, port...)

		_, err = server.Write(reply)
		if err != nil {
			return xerrors.Errorf("socks write addr type not support response failed: %w", err)
		}
		return xerrors.New("socks addr type not support")
	}

	return nil
}

func (server *SocksServer) Reply(ip net.IP, port uint16, field ResponseType) error {
	switch field {
	default:
		return xerrors.Errorf("not support reply filed %d", field)

	case Success, ServerFailed, ConnNotAllowed, NetworkUnreachable, ConnRefused, TTLExpired, CmdNotSupport, AddrTypeNotSupport:
	}

	reply := []byte{Version, field, 0}
	if ipv4 := ip.To4(); ipv4 != nil {
		reply = append(reply, TypeIPv4)
		reply = append(reply, ipv4...)
	} else {
		reply = append(reply, TypeIPv6)
		reply = append(reply, ip...)
	}

	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	reply = append(reply, pb...)

	if _, err := server.Write(reply); err != nil {
		return xerrors.Errorf("socks write reply failed: %w", err)
	}

	return nil
}
