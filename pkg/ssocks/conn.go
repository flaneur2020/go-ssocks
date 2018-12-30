package ssocks

import "net"

type ShadowsocksConn struct {
	conn       net.Conn
	cipher     *Cipher
	remoteAddr string
}

func NewShadowsocksConn(remoteAddr string, cipher *Cipher, conn net.Conn) *ShadowsocksConn {
	c := &ShadowsocksConn{
		remoteAddr: remoteAddr,
		cipher:     cipher,
		conn:       conn,
	}
	return c
}

func Dial(remoteAddr, password, cipherMethod string) (*ShadowsocksConn, error) {
	cipher, err := NewCipher()
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return nil, err
	}
	ssconn := NewShadowsocksConn(remoteAddr, cipher, conn)
	return ssconn, nil
}

func (sc *ShadowsocksConn) Close() {
	sc.conn.Close()
}
