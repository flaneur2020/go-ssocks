package ssocks

import (
	"crypto/md5"
)

type Cipher struct {
}

func NewCipher() (*Cipher, error) {
	return nil, nil
}

type Encrypter struct {
	Key          []byte
	IV           []byte
	cipherMethod string
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

func NewEncrypter(cipherMethod, password []byte) (*Encrypter, error) {
	// key := evpBytesToKey(password, 12)
	// block, err := aes.NewCipher(key)
	//if err != nil {
	//	return nil, err
	//}
	return nil, nil
}
