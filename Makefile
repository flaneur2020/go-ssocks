all: build

build:
	go build -o bin/ssocks-local cmd/ssocks-local/main.go

test:
	go test -v -cover ./...
