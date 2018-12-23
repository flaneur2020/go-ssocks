package main

import (
	"github.com/Fleurer/go-ssocks/pkg/ssocks"
)

func main() {
	s := ssocks.NewLocalServer("0.0.0.0:9292")
	s.ListenAndServe()
}
