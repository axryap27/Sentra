# Developer shortcuts. CI calls the same targets.
GO_DIR := analyzer-go

.PHONY: all go-build go-test go-vet go-fmt go-fmt-check ts-build lint test

all: go-build ts-build

go-build:
	cd $(GO_DIR) && CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o ../bin/local/sentra-analyzer .

go-test:
	cd $(GO_DIR) && go test ./...

go-vet:
	cd $(GO_DIR) && go vet ./...

go-fmt:
	cd $(GO_DIR) && gofmt -w .

go-fmt-check:
	@cd $(GO_DIR) && test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

ts-build:
	npm run typecheck && npm run build

lint: go-vet go-fmt-check
	npm run lint && npm run format:check

test: go-test
