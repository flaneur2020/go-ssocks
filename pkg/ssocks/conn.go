package ssocks

import (
	"io"
	"net"

	"git.in.zhihu.com/go/box/log"
)

type ShadowsocksConn struct {
	conn       net.Conn
	cipher     *Cipher
	decIv      []byte
	encIv      []byte
	readBuf    []byte
	writeBuf   []byte
	remoteAddr string
}

func NewShadowsocksConn(remoteAddr string, cipher *Cipher, conn net.Conn) *ShadowsocksConn {
	c := &ShadowsocksConn{
		remoteAddr: remoteAddr,
		cipher:     cipher,
		conn:       conn,
		decIv:      nil,
		encIV:      nil,
		readBuf:    make([]byte, 512),
		writeBuf:   make([]byte, 512),
	}
	return c
}

func Dial(remoteAddr, password, cipherMethod string) (*ShadowsocksConn, error) {
	cipher, err := NewCipher(cipherMethod, password)
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

func (sc *ShadowsocksConn) Read(b []byte) (int, error) {
	if sc.decIv == nil {
		decIv := make([]byte, sc.cipher.IvLen)
		_, err := io.ReadFull(sc.conn, decIv)
		if err != nil {
			return 0, err
		}
		sc.cipher.SetupDecryptIV(decIv)
		sc.decIv = decIv
	}
	cipherBuf := sc.readBuf
	if len(b) > len(cipherBuf) {
		log.Printf("ShadowsocksConn.Read got buf(%d) longer than readBuf(%d)\n", len(b), len(cipherBuf))
		cipherBuf = make([]byte, len(b))
	} else {
		cipherBuf = cipherBuf[:len(b)]
	}
	n, err := sc.conn.Read(cipherBuf)
	if n > 0 {
		sc.cipher.Decrypt(b[0:n], cipherBuf[0:n])
	}
	return n, err
}

func (sc *ShadowsocksConn) Write(b []byte) (int, error) {
	if sc.encIv == nil {
		n, err := sc.conn.Write(sc.encIv)
		if err != nil {
			return 0, err
		}
		sc.encIv = sc.cipher.encIv
	}
	cipherBuf := sc.writeBuf
	if len(b) > len(cipherBuf) {
		log.Printf("ShadowsocksConn.Write got buf(%d) longer than readBuf(%d)\n", len(b), len(cipherBuf))
		cipherBuf = make([]byte, len(b))
	} else {
		cipherBuf = cipherBuf[:len(b)]
	}
	sc.cipher.Decrypt(cipherBuf, b)
	return c.conn.Write(cipherBuf)
}
