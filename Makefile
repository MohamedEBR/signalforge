UV ?= uv

.PHONY: install format lint validate test replay benchmark schemas audit build check

install:
	$(UV) sync --extra dev

format:
	$(UV) run black src tests scripts
	$(UV) run ruff check --fix src tests scripts

lint:
	$(UV) run black --check src tests scripts
	$(UV) run ruff check src tests scripts

validate:
	$(UV) run signalforge validate-rules rules

test:
	$(UV) run pytest

replay:
	$(UV) run signalforge replay scenarios --rules rules \
		--json reports/replay.json --markdown reports/replay.md

benchmark:
	$(UV) run python scripts/benchmark.py --output reports/benchmark.json

schemas:
	$(UV) run python scripts/export_schemas.py

audit:
	$(UV) run pip-audit

build:
	$(UV) build

check: lint validate test replay schemas audit build
