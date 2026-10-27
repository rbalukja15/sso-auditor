# Developer entry points. Every target runs through uv, so the tool versions are
# the ones pinned in uv.lock.

.DEFAULT_GOAL := help
UV ?= uv
RUN := $(UV) run --locked

.PHONY: help dev lint fmt test eval

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\n", $$1, $$2}'

dev: ## Install the packages and dev tools, and set up the pre-commit hook
	$(UV) sync --locked
	$(RUN) pre-commit install

lint: ## Lint, check formatting and type-check
	$(RUN) ruff check .
	$(RUN) ruff format --check .
	$(RUN) mypy

fmt: ## Format and apply safe lint fixes
	$(RUN) ruff format .
	$(RUN) ruff check --fix .

test: ## Run the test suite
	$(RUN) pytest

eval: ## Score the rules against the fixtures (#15)
	@echo "make eval: not implemented yet (#15)"
