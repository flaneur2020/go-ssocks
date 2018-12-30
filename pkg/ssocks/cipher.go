package ssocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"io"
)

type Cipher struct {
}

func NewCipher() (*Cipher, error) {
	return nil, nil
}

type Encrypter struct {
	Key    []byte
	IV     []byte
	stream cipher.Stream
}

func NewEncrypter(cipherMethod, password []byte, keyLen, ivLen int) (*Encrypter, error) {
	key := evpBytesToKey(password, keyLen)
	iv := genIV(ivLen)
	stream, err := newAesCfbStream(key, iv)
	if err != nil {
		return nil, err
	}
	enc := &Encrypter{
		IV:     iv,
		Key:    key,
		stream: stream,
	}
	return enc, nil
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
