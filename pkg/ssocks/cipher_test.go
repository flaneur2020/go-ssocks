package ssocks

import (
	"bytes"
	"testing"
)

func TestCipher(t *testing.T) {
	c, err := NewCipher("aes-128-cfb", "foobar")
	if err != nil {
		t.Errorf("fail to NewCipher: %s", err)
	}
	c.SetupDecryptIV(c.EncIv)
	originBuf := []byte("hello world")
	cipherBuf := make([]byte, len(originBuf))
	plainBuf := make([]byte, len(originBuf))
	c.Encrypt(cipherBuf, originBuf)
	c.Decrypt(plainBuf, cipherBuf)
	if !bytes.Equal(originBuf, plainBuf) {
		t.Errorf("originBuf(%s) != plainBuf(%s)", originBuf, plainBuf)
	}
}

func TestCipher2(t *testing.T) {
	c, err := NewCipher("aes-128-cfb", "foobar")
	if err != nil {
		t.Errorf("fail to NewCipher: %s", err)
	}
	c.SetupDecryptIV(c.EncIv)
	originBuf := []byte("hello world bblah blah lah  blah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah lblah l")
	cipherBuf := make([]byte, len(originBuf))
	plainBuf := make([]byte, len(originBuf))
	c.Encrypt(cipherBuf, originBuf)
	c.Decrypt(plainBuf, cipherBuf)
	if !bytes.Equal(originBuf, plainBuf) {
		t.Errorf("originBuf(%s) != plainBuf(%s)", originBuf, plainBuf)
	}
}

func TestEvpBytesToKey(t *testing.T) {
	key := evpBytesToKey([]byte("foobar"), 32)
	expectedKey := []byte{0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12, 0xc6, 0x3f, 0x56, 0x83, 0x78, 0x52, 0x96, 0x14, 0xd2, 0x2d, 0xdb, 0x49, 0x23, 0x7d, 0x2f, 0x60, 0xbf, 0xdf}
	if !bytes.Equal(key, expectedKey) {
		t.Errorf("key(%s) != expectedKey(%s)", key, expectedKey)
	}
}
