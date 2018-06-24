build:
	go build -o ./ssocks-client ./main.go
test:
	go test -v -cover ./...
