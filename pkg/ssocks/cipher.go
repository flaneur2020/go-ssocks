package ssocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
)

type Cipher struct {
	cipherMethod string
	key          []byte
	encStream    cipher.Stream
	decStream    cipher.Stream
}

type cipherMethod struct {
	KeyLen        int
	IvLen         int
	NewStreamFunc func(key []byte, iv []byte) (cipher.Stream, error)
}

var cipherMethodMap = map[string]cipherMethod{
	"aes-128-cfb": {16, 16, newAesCfbStream},
}

func NewCipher(cipherMethod string, password []byte) (*Cipher, error) {
	m := cipherMethodMap[cipherMethod]
	key := evpBytesToKey(password, m.KeyLen)
	iv := genIV(m.IvLen)
	encStream, err := m.NewStreamFunc(key, iv)
	if err != nil {
		panic(fmt.Sprintf("fail to new encStream: %s", err))
	}
	c := Cipher{
		key:       key,
		encStream: encStream,
		decStream: nil,
	}
	return &c, nil
}

func (c *Cipher) setupDecryptIV(iv []byte) {
	if c.decStream != nil {
		panic("decStream has already been setuped")
	}
	m := cipherMethodMap[c.cipherMethod]
	decStream, err := m.NewStreamFunc(c.key, iv)
	if err != nil {
		panic(fmt.Sprintf("fail to new decStream: %s", err))
	}
	c.decStream = decStream
}

func (c *Cipher) encrypt(dst, src []byte) {
	c.encStream.XORKeyStream(dst, src)
}

func (c *Cipher) decrypt(dst, src []byte) {
	if c.decStream == nil {
		panic("decStream has not been setuped yet, please setupDecryptIV() first")
	}
	c.decStream.XORKeyStream(dst, src)
}

func newAesCfbStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
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
