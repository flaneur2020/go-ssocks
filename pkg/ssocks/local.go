package ssocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

type LocalServer struct {
	listenAddr string
}

type socksRequest struct {
	Ver      byte
	Cmd      byte
	AddrType byte
	Addr     string
	Port     uint16
}

var (
	errVer      = errors.New("socks version not supported")
	errCmd      = errors.New("socks command not supported")
	errAddrType = errors.New("socks addrType not supported")
)

const (
	SocksVer5       = 5
	SocksCmdConnect = 1
	SocksMaxAddrLen = 1 + 1 + 255 + 2 // Maximum size of SOCKS address in bytes
)

const (
	addrTypeIPv4   = 1
	addrTypeDomain = 3
	addrTypeIPv6   = 4
)

func NewLocalServer(listenAddr string) *LocalServer {
	return &LocalServer{listenAddr: listenAddr}
}

func (s *LocalServer) ListenAndServe() {
	l, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening %s", s.listenAddr)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("local:accept err:", err)
		}
		go s.handleConnection(conn)
	}
}

func (s *LocalServer) handleConnection(conn net.Conn) {
	// the client will create a new SOCKS connection on EVERY new TCP connection
	err := s.handshake(conn)
	if err != nil {
		log.Printf("SOCKS5 handshake error: %s\n", err)
		return
	}
	req, err := readRequest(conn)
	if err != nil {
		log.Printf("SOCKS5 readRequest error: %s\n", err)
		return
	}
	log.Printf("get request: %v\n", req)
}

func (s *LocalServer) handshake(conn net.Conn) error {
	const (
		iVer       = 0
		iNumMethod = 1
	)
	buf := make([]byte, SocksMaxAddrLen)
	// read Ver, NumMethod
	_, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return err
	}
	if buf[iVer] != SocksVer5 {
		return errVer
	}
	// read Method
	len := int(buf[iNumMethod]) + 2
	_, err = io.ReadFull(conn, buf[2:len])
	if err != nil {
		return err
	}
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{SocksVer5, 0})
	return err
}

func readRequest(conn net.Conn) (*socksRequest, error) {
	// https://www.ietf.org/rfc/rfc1928.txt
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	buf := make([]byte, 263)
	req := socksRequest{}
	offset := 0
	// read the first 4 bytes as request head
	n, err := io.ReadFull(conn, buf[0:4])
	if err != nil {
		return nil, err
	}
	req.Ver = buf[offset]
	req.Cmd = buf[offset+1]
	req.AddrType = buf[offset+3]
	offset += n
	// read the addr by addr type
	switch req.AddrType {
	case addrTypeIPv4:
		n, err = io.ReadFull(conn, buf[offset:offset+net.IPv4len])
	case addrTypeIPv6:
		n, err = io.ReadFull(conn, buf[offset:offset+net.IPv6len])
	case addrTypeDomain:
		n, err = readVarBuf(conn, buf[offset:])
	default:
		return nil, errAddrType
	}
	if err != nil {
		return nil, err
	}
	req.Addr = string(buf[offset : offset+n])
	offset += n
	// read the port
	n, err = io.ReadFull(conn, buf[offset:(offset+2)])
	req.Port = binary.BigEndian.Uint16(buf[offset : offset+2])
	return &req, nil
}

func readVarBuf(conn net.Conn, buf []byte) (int, error) {
	_, err := io.ReadFull(conn, buf[0:1])
	if err != nil {
		return 0, err
	}
	len := buf[0]
	n, err := io.ReadFull(conn, buf[1:1+len])
	if n != int(len) {
		panic(fmt.Sprintf("expected n(%d) == len(%d)", n, len))
	}
	return n + 1, err
}