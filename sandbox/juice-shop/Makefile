SHELL := /bin/bash
.DEFAULT_GOAL := help

LOCALSTACK_URL ?= http://localhost:4566
JUICE_URL      ?= http://localhost:3000

.PHONY: help up down wipe tf-init tf-plan tf-apply tf-destroy verify pentest demo

help:
	@echo "Juice Shop on ECS Fargate (LocalStack) — TrustGraph Security demo"
	@echo ""
	@echo "  HACKATHON QUICKSTART"
	@echo "    make learn       # guided interactive walkthrough (recommended)"
	@echo "    make compare     # diff two previous runs side-by-side"
	@echo ""
	@echo "  INFRASTRUCTURE"
	@echo "    make demo        # non-interactive: up → tf-apply → verify → pentest"
	@echo "    make up          # start LocalStack + Juice Shop containers"
	@echo "    make tf-apply    # provision ECS/ALB/VPC in LocalStack"
	@echo "    make verify      # curl LocalStack + Juice Shop"
	@echo "    make down        # stop containers"
	@echo "    make wipe        # stop + delete state + tf state"

up:
	docker compose -f docker-compose.localstack.yml up -d
	@echo "Waiting for LocalStack ..."
	@until curl -sf $(LOCALSTACK_URL)/_localstack/health >/dev/null; do sleep 2; done
	@echo "LocalStack ready."
	@echo "Waiting for Juice Shop ..."
	@until curl -sf $(JUICE_URL)/rest/admin/application-version >/dev/null; do sleep 2; done
	@echo "Juice Shop ready at $(JUICE_URL)"

down:
	docker compose -f docker-compose.localstack.yml down

wipe:
	docker compose -f docker-compose.localstack.yml down -v
	rm -rf .localstack terraform/.terraform terraform/terraform.tfstate*

tf-init:
	cd terraform && terraform init -upgrade

tf-plan: tf-init
	cd terraform && terraform plan -out=tfplan

tf-apply: tf-init
	cd terraform && terraform apply -auto-approve

tf-destroy:
	cd terraform && terraform destroy -auto-approve

verify:
	@echo "== LocalStack health =="; curl -sf $(LOCALSTACK_URL)/_localstack/health | head -c 400; echo
	@echo "== ECS clusters =="; awslocal ecs list-clusters || true
	@echo "== ALB =="; awslocal elbv2 describe-load-balancers --query 'LoadBalancers[].DNSName' || true
	@echo "== Juice Shop banner =="; curl -sf $(JUICE_URL)/rest/admin/application-version

pentest:
	cd ../../prototype && python repo_to_tasks.py https://github.com/juice-shop/juice-shop
	@echo "Tasks written under ../../prototype/runs/juice-shop_juice-shop/<timestamp>/"

learn:
	cd ../../prototype && python guided_demo.py

compare:
	cd ../../prototype && printf '2\n' | python guided_demo.py

demo: up tf-apply verify pentest
	@echo ""
	@echo "Demo complete."
	@echo "  Juice Shop UI : $(JUICE_URL)"
	@echo "  Pentest tasks : ../../prototype/tasks.json"
