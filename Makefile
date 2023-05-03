.PHONY: all

all: housekeeping test coverage

housekeeping:
	golangci-lint run --fix ./...

protoc:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		internal/helloworld/helloworld.proto

test:
	go test -v ./...

coverage:
	go test --cover -covermode=set -coverprofile=coverage.cov \
		-coverpkg=$(go list ./...) \
		./...
	go tool cover -func coverage.cov
