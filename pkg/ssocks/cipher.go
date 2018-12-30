package ssocks

type Cipher struct {
	password     string
	cipherMethod string
}

func NewCipher(cipherMethod, password string) (*Cipher, error) {
	c := &Cipher{
		password:     password,
		cipherMethod: cipherMethod,
	}
	return c, nil
}
