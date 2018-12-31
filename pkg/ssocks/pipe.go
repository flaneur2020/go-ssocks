package ssocks

import (
	"io"
	"log"
)

func Pipe(name string, src io.Reader, dst io.Writer) {
	defer log.Printf("%s pipe stopped", name)
	buf := make([]byte, 1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			log.Printf("%s pipe read err: %v", name, err)
			break
		}
		if n > 0 {
			_, err = dst.Write(buf[0:n])
			log.Printf("%s pipe write buf: %s n:%d", name, buf[0:n], n)
			if err != nil {
				log.Printf("%s pipe write err: %v", name, err)
				break
			}
		}
	}
}
