package ssocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var errInvalidCipherMethod = errors.New("invalid cipher method")

type Cipher struct {
	IVLen        int
	key          []byte
	cipherMethod string
	encStream    cipher.Stream
	decStream    cipher.Stream
}

type cipherMethod struct {
	KeyLen       int
	IVLen        int
	NewEncStream func(key []byte, iv []byte) (cipher.Stream, error)
	NewDecStream func(key []byte, iv []byte) (cipher.Stream, error)
}

var cipherMethodMap = map[string]cipherMethod{
	"aes-128-cfb": {16, 16, newAesCfbEncStream, newAesCfbDecStream},
}

func NewCipher(cipherMethod string, password string) (*Cipher, error) {
	m, ok := cipherMethodMap[cipherMethod]
	if !ok {
		return nil, errInvalidCipherMethod
	}
	key := evpBytesToKey([]byte(password), m.KeyLen)
	c := Cipher{
		key:          key,
		IVLen:        m.IVLen,
		encStream:    nil,
		decStream:    nil,
		cipherMethod: cipherMethod,
	}
	return &c, nil
}

func (c *Cipher) SetupEntrypt() []byte {
	if c.encStream != nil {
		panic("decStream has already been setuped")
	}
	m, ok := cipherMethodMap[c.cipherMethod]
	if !ok {
		panic(fmt.Sprintf("cipherMethod(%s) not found", c.cipherMethod))
	}
	encIv := genIV(m.IVLen)
	encStream, err := m.NewEncStream(c.key, encIv)
	if err != nil {
		panic(fmt.Sprintf("fail to new decStream: %s", err))
	}
	c.encStream = encStream
	return encIv
}

func (c *Cipher) SetupDecrypt(iv []byte) {
	if c.decStream != nil {
		panic("decStream has already been setuped")
	}
	m, ok := cipherMethodMap[c.cipherMethod]
	if !ok {
		panic(fmt.Sprintf("cipherMethod(%s) not found", c.cipherMethod))
	}
	decStream, err := m.NewDecStream(c.key, iv)
	if err != nil {
		panic(fmt.Sprintf("fail to new decStream: %s", err))
	}
	c.decStream = decStream
}

func (c *Cipher) Encrypt(dst, src []byte) {
	if c.encStream == nil {
		panic("encStream has not been setuped yet, please SetupEntrypt() first")
	}
	c.encStream.XORKeyStream(dst, src)
}

func (c *Cipher) Decrypt(dst, src []byte) {
	if c.decStream == nil {
		panic("decStream has not been setuped yet, please SetupDecrypt() first")
	}
	c.decStream.XORKeyStream(dst, src)
}

func newAesCfbEncStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	return stream, nil
}

func newAesCfbDecStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, iv)
	return stream, nil
}

// evpBytesToKey implements the Openssl EVP_BytesToKey method
// https://github.com/walkert/go-evp/blob/master/evp.go
func evpBytesToKey(password []byte, keyLen int) (key []byte) {
	var (
		concat   []byte
		lastHash []byte
	)
	h := md5.New()
	for ; len(concat) < keyLen; h.Reset() {
		// concatenate lastHash, data and salt and write them to the hash
		h.Write(append(lastHash, password...))
		// passing nil to Sum() will return the current hash value
		lastHash = h.Sum(nil)
		// append lastHash to the running total bytes
		concat = append(concat, lastHash...)
	}
	return concat[:keyLen]
}

func genIV(ivLen int) []byte {
	iv := make([]byte, ivLen)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}
	return iv
}
