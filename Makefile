build: 
	@go build -o bin/server1 cmd/main.go
test: 
	@go test -v ./...
run: build
	@./bin/server1