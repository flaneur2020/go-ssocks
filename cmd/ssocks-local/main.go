package main

import (
	"flag"
	"fmt"

	"github.com/Fleurer/go-ssocks/pkg/ssocks"
)

type CmdOptions struct {
	ServerAddr   string
	ListenPort   int
	Password     string
	CipherMethod string
}

func main() {
	opt := CmdOptions{}
	flag.StringVar(&opt.ServerAddr, "s", "", "server address")
	flag.IntVar(&opt.ListenPort, "P", 9090, "listen port")
	flag.StringVar(&opt.Password, "p", "", "password")
	flag.StringVar(&opt.CipherMethod, "m", "", "cipher method")
	flag.Parse()

	listenAddr := fmt.Sprintf("0.0.0.0:%d", opt.ListenPort)
	s, err := ssocks.NewLocalServer(listenAddr, opt.ServerAddr, opt.Password, opt.CipherMethod)
	if err != nil {
		fmt.Printf("NewLocalServer error: %s\n", err)
	}
	s.ListenAndServe()
}
