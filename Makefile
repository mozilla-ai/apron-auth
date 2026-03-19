.PHONY: ensure-scripts-exec
ensure-scripts-exec:
	@chmod +x scripts/* || true

.PHONY: setup
setup: ensure-scripts-exec
	@scripts/setup_uv.sh

.PHONY: test
test:
	@uv run -m pytest tests

.PHONY: test-integration
test-integration:
	@APRON_AUTH_INTEGRATION_TESTS=1 uv run -m pytest tests -m integration -v

.PHONY: lint
lint:
	@uv run pre-commit run --all-files
