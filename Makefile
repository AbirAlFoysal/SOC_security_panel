# Keep Makefile, anon-control.py, and anon-install.sh together.
.DEFAULT_GOAL := help
.PHONY: help anon stop install status
CONTROL := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))anon-control.py
INSTALLER := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))anon-install.sh
export IFACE

help:
	@printf '%s\n' 'make install anon  Install Anonsurf CLI and macchanger' 'make anon          Change MAC and start Anonsurf' 'make stop anon     Stop Anonsurf and restore network settings' 'make status        Show Anonsurf status'

ifneq ($(filter install,$(MAKECMDGOALS)),)
ifneq ($(filter stop,$(MAKECMDGOALS)),)
$(error Run install and stop separately)
endif
anon: install
	@:
else ifneq ($(filter stop,$(MAKECMDGOALS)),)
anon: stop
	@:
else
anon:
	@sudo /usr/bin/python3 "$(CONTROL)" start "$(IFACE)"
endif

stop:
	@sudo /usr/bin/python3 "$(CONTROL)" stop

install:
	@/bin/bash "$(INSTALLER)"

status:
	@sudo /usr/bin/anonsurf status

# Django workspace is the default; the original server remains available.
.PHONY: run run-legacy
PYTHON ?= python3
HOST ?= 127.0.0.1
PORT ?= 8000
ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
APP_DIR := $(ROOT_DIR)master_app
CONTINUM_DIR := $(ROOT_DIR)continum
VENV_PYTHON ?= $(ROOT_DIR).venv/bin/python

run:
	@if [ ! -x "$(VENV_PYTHON)" ]; then printf '%s\n' 'Shared .venv not found. Create it and install Continum dependencies: python3 -m venv .venv && .venv/bin/python -m pip install -r continum/requirements.txt'; exit 1; fi
	@cd "$(CONTINUM_DIR)" && "$(VENV_PYTHON)" manage.py runserver "$(HOST):$(PORT)"

run-legacy:
	@$(PYTHON) "$(APP_DIR)/dev.py" --host "$(HOST)" --port "$(PORT)"
