package ssocks

import (
	"io"
	"net"
	"time"

	"log"
)

type ShadowsocksConn struct {
	conn           net.Conn
	cipher         *Cipher
	decIV          []byte
	encIV          []byte
	readBuf        []byte
	writeBuf       []byte
	remoteAddr     string
	firstWriteTime time.Time
	firstReadTime  time.Time
}

func NewShadowsocksConn(remoteAddr string, cipher *Cipher, conn net.Conn) *ShadowsocksConn {
	c := &ShadowsocksConn{
		remoteAddr:     remoteAddr,
		cipher:         cipher,
		conn:           conn,
		decIV:          nil,
		encIV:          nil,
		readBuf:        make([]byte, 2048),
		writeBuf:       make([]byte, 2048),
		firstReadTime:  time.Unix(0, 0),
		firstWriteTime: time.Unix(0, 0),
	}
	return c
}

func Dial(remoteAddr, password, cipherMethod string, rawAddr []byte, readTimeout time.Duration) (*ShadowsocksConn, error) {
	cipher, err := NewCipher(cipherMethod, password)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	ssconn := NewShadowsocksConn(remoteAddr, cipher, conn)
	_, err = ssconn.Write(rawAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssconn, nil
}

func (sc *ShadowsocksConn) Close() {
	sc.conn.Close()
}

func (sc *ShadowsocksConn) Read(b []byte) (int, error) {
	if sc.decIV == nil {
		decIV := make([]byte, sc.cipher.IVLen)
		_, err := io.ReadFull(sc.conn, decIV)
		if err != nil {
			log.Printf("read dec iv failed")
			return 0, err
		}
		sc.cipher.SetupDecrypt(decIV)
		sc.firstReadTime = time.Now()
		sc.decIV = decIV
	}
	// log.Printf("ssconn: read: decIV: %v\n", sc.decIv)
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
	if sc.encIV == nil {
		encIV := sc.cipher.SetupEntrypt()
		_, err := sc.conn.Write(encIV)
		if err != nil {
			return 0, err
		}
		sc.firstWriteTime = time.Now()
		sc.encIV = encIV
	}
	cipherBuf := sc.writeBuf
	if len(b) > len(cipherBuf) {
		log.Printf("ShadowsocksConn.Write got buf(%d) longer than readBuf(%d)\n", len(b), len(cipherBuf))
		cipherBuf = make([]byte, len(b))
	} else {
		cipherBuf = cipherBuf[:len(b)]
	}
	sc.cipher.Encrypt(cipherBuf, b)
	n, err := sc.conn.Write(cipherBuf)
	return n, err
}

func (sc *ShadowsocksConn) Latency() time.Duration {
	d := sc.firstReadTime.Sub(sc.firstWriteTime)
	return d
}
