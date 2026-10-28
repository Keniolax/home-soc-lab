# home-soc-lab. Run `make` on its own to list the targets.

SHELL := /bin/bash
COMPOSE := docker compose
# The first start pulls about 7.5 GB of images and builds the security index.
WAIT_TIMEOUT := 900

.DEFAULT_GOAL := help
.PHONY: help up down test status logs clean audit harden coverage hunt

help: ## List the targets
	@awk -F ':.*## ' '/^[a-z-]+:.*## / { printf "  make %-8s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.env: .env.example
	@scripts/init-env.sh

up: .env ## Start the lab and wait until every service is healthy
	@scripts/preflight.sh
	@# The victim agent tails this file for the network sensor's alerts (make
	@# hunt). The agent must find it at start to read it as it grows, so create
	@# it empty here, before the victim container starts.
	@mkdir -p tmp/net-logs/suricata && touch tmp/net-logs/suricata/eve.json
	$(COMPOSE) up -d --build --wait --wait-timeout $(WAIT_TIMEOUT)
	@port=$$(grep -E '^DASHBOARD_PORT=' .env | cut -d= -f2); \
	echo; \
	echo "Lab is up."; \
	echo "  Dashboard: https://localhost:$${port:-8443}"; \
	echo "  User:      admin"; \
	echo "  Password:  the INDEXER_ADMIN_PASSWORD line in .env"; \
	echo "  Your browser will warn about the certificate: the lab signs its own."; \
	echo "  Next:      make test"

test: ## Make failed SSH logins on the victim and check that Wazuh alerts
	@scripts/test-detection.sh

audit: ## Score the victim with Lynis and the CIS checks (LABEL=before or after)
	@scripts/audit.sh $(or $(LABEL),now)

coverage: ## Emulate ATT&CK techniques and map what the SIEM detects (see docs/coverage.md)
	@coverage/run-coverage.sh

hunt: ## Run the network sensor over a malicious capture and hunt its C2 (see docs/hunt.md)
	@network/fetch-pcap.sh
	@network/run-sensor.sh
	@python3 network/hunt.py
	@network/check-siem.sh

harden: ## Harden the victim to a CIS subset (see docs/hardening.md)
	$(COMPOSE) -f compose.yaml -f compose.harden.yaml up -d --wait --wait-timeout 300 victim
	$(COMPOSE) cp victim/harden.sh victim:/usr/local/sbin/harden
	$(COMPOSE) exec -T victim bash /usr/local/sbin/harden

status: ## Show each service and its health
	$(COMPOSE) ps --all

logs: ## Follow the logs of every service
	$(COMPOSE) logs -f --tail=50

down: ## Stop the lab and delete its containers, volumes and certificates
	$(COMPOSE) --profile test down --volumes --remove-orphans

clean: down ## Also delete .env (new passwords next time) and the victim image
	rm -f .env
	-docker image rm home-soc-lab/victim:local
	rm -rf tmp/last-test
