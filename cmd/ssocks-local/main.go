package main

import (
	"fmt"

	"github.com/Fleurer/go-ssocks/pkg/ssocks"
)

func main() {
	s, err := ssocks.NewLocalServer("0.0.0.0:9292", "localhost:9090", "123", "aes-128-cfb")
	if err != nil {
		fmt.Printf("NewLocalServer error: %s\n", err)
	}
	s.ListenAndServe()
}
