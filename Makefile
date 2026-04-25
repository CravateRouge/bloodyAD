# bloodyAD developer convenience targets.
#
# Most targets assume you have a virtualenv active. Create one with:
#   uv venv --python 3.13 .venv && source .venv/bin/activate && uv pip install -e . -r requirements-dev.txt

.PHONY: help install install-dev test test-unit test-functional test-auth lint clean

PYTHON ?= python3

help:
	@echo "bloodyAD make targets:"
	@echo "  install           Editable install of bloodyAD into the active venv"
	@echo "  install-dev       Install + dev deps (impacket, certipy-ad)"
	@echo "  test-unit         Run AD-free unit tests (no lab required)"
	@echo "  test-functional   Run functional tests (requires tests/secrets.json + running DC)"
	@echo "  test-auth         Run authentication tests (requires DC + AD CS)"
	@echo "  test              test-unit + test-functional + test-auth"
	@echo "  clean             Remove build artifacts + __pycache__"

install:
	$(PYTHON) -m pip install -e .

install-dev: install
	$(PYTHON) -m pip install -r requirements-dev.txt

test-unit:
	$(PYTHON) -m unittest tests.test_formatters tests.test_msldap_module tests.unit_test -v

test-functional:
	@test -f tests/secrets.json || ( \
	    echo "tests/secrets.json not found. Copy tests/secrets.json.example and fill it in."; \
	    echo "See tests/lab/README.md for lab setup."; exit 1)
	$(PYTHON) -m unittest tests.test_functional -v

test-auth:
	@test -f tests/secrets.json || ( \
	    echo "tests/secrets.json not found. Copy tests/secrets.json.example and fill it in."; \
	    echo "See tests/lab/README.md for lab setup."; exit 1)
	$(PYTHON) -m unittest tests.test_authentication -v

test: test-unit test-functional test-auth

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf build dist *.egg-info
	rm -rf tests/tmp
