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

# Cybersecurity web app with development auto reload.
.PHONY: run
PYTHON ?= python3
HOST ?= 127.0.0.1
PORT ?= 8000
APP_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))master_app

run:
	@$(PYTHON) "$(APP_DIR)/dev.py" --host "$(HOST)" --port "$(PORT)"
