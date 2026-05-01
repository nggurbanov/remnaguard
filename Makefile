.PHONY: test vet lint race fuzz build validate route-check docker contract-local

test:
	go test ./...

race:
	go test -race ./...

fuzz:
	go test ./internal/httputil -fuzz=Fuzz -fuzztime=10s
	go test ./internal/jsonpolicy -fuzz=Fuzz -fuzztime=10s

vet:
	go vet ./...

lint:
	golangci-lint run

build:
	go build -trimpath -ldflags "-s -w" ./cmd/remnaguard

validate:
	go run ./cmd/remnaguard validate -c configs/remnaguard.example.yaml

route-check:
	go run ./cmd/remnaguard routes check-openapi --spec internal/routes/testdata/remnawave-2.7.4-openapi-min.json --strict

docker:
	docker build -t remnaguard:local .

contract-local:
	REMNAGUARD_DESTRUCTIVE_CONTRACT_TESTS=1 \
	REMNAGUARD_STAGING_BASE_URL=http://127.0.0.1:3300 \
	REMNAGUARD_STAGING_BEARER_FILE=$${REMNAGUARD_STAGING_BEARER_FILE:-$$(pwd)/.local/remnawave-staging/api-token.txt} \
	go test ./internal/contract -run TestLocalStagingDestructiveContract -count=1 -v
