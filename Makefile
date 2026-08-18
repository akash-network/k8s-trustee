SHELL := /usr/bin/env bash

ENV ?= staging

.PHONY: validate test render render-routes core-readiness readiness qualification-status verify-source cluster-preflight smoke image-smoke

validate:
	./scripts/validate.sh

test:
	python3 -m unittest discover -s tests -p 'test_*.py'

render:
	kubectl kustomize deploy/overlays/$(ENV)

render-routes:
	kubectl kustomize deploy/routes/$(ENV)

readiness:
	./scripts/readiness.sh $(ENV)

core-readiness:
	python3 ./scripts/readiness.py core-readiness qualification

qualification-status:
	python3 ./scripts/readiness.py qualification-status qualification

verify-source:
	./scripts/verify-source-lock.sh $(ENV) "$(TRUSTEE_CHECKOUT)"

cluster-preflight:
	./scripts/cluster-preflight.sh $(ENV)

smoke:
	./scripts/smoke.sh

image-smoke:
	./scripts/image-smoke.sh
