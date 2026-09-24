.PHONY: up demo down test check benchmark logs
up:
	./bin/dev
demo: up
	./bin/passport demo
down:
	docker compose down
test:
	go test -race ./...
	npm test
	cargo test --manifest-path workers/policy-proof/Cargo.toml --locked
check:
	npm run format:check
	npm run typecheck
	go vet ./...
	cargo fmt --manifest-path workers/policy-proof/Cargo.toml --check
benchmark:
	./bin/passport benchmark
logs:
	docker compose logs --tail=100 -f
