# ==============================================================================
# Enterprise AP Invoice Automation Platform — Developer Makefile
# Single Source of Truth: CLAUDE.md §14
# ==============================================================================

SHELL := /bin/bash
PYTHON ?= python3
PORT_API ?= 8000
PORT_UI ?= 8501

# Strict Offline Test Flags
OFFLINE_ENV := PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
               USE_LOCAL_SQLITE=true \
               USE_FAKE_REDIS=true \
               USE_MOCK_AOAI=true \
               SAMPLE_DATA_DIR=./sample_data

.PHONY: help install run-api run-ui test test-unit test-integration test-eval lint format clean seed-data

help: ## Show available make targets
	@echo "Available commands for Enterprise AP Automation Platform:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install package in editable mode with development dependencies
	$(PYTHON) -m pip install -e ".[dev]"

run-api: ## Run FastAPI backend locally on port 8000
	uvicorn src.api.main:app --reload --port $(PORT_API)

run-ui: ## Run Streamlit UI dashboard on port 8501
	streamlit run src/ui/app.py --server.port $(PORT_UI)

test: ## Run all tests offline (100% mocked Azure services)
	$(OFFLINE_ENV) pytest -p pytest_asyncio -v

test-unit: ## Run fast unit tests offline
	$(OFFLINE_ENV) pytest -p pytest_asyncio -v tests/unit/

test-integration: ## Run integration tests with mocked Azure services
	$(OFFLINE_ENV) pytest -p pytest_asyncio -v tests/integration/

test-eval: ## Run automated evaluation suite against ground truth
	$(OFFLINE_ENV) pytest -p pytest_asyncio -v tests/evaluation/

lint: ## Run ruff linter
	ruff check src/ tests/

format: ## Run ruff auto-formatter
	ruff format src/ tests/

clean: ## Remove temporary python cache, pytest, and ruff artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[cod]" -delete
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info

seed-data: ## Generate synthetic 300-invoice dataset and ground-truth JSONs
	$(PYTHON) scratch/generate_mock_data.py
