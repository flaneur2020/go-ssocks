package ssocks

import (
	"io"
	"log"
)

func Pipe(name string, src io.Reader, dst io.Writer) {
	buf := make([]byte, 1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			log.Printf("%s pipe read err: %v", name, err)
			break
		}
		if n > 0 {
			_, err = dst.Write(buf[0:n])
			if err != nil {
				log.Printf("%s pipe write err: %v", name, err)
				break
			}
		}
	}
}
