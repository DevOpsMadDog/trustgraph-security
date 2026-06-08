COMPOSE         := docker compose -f infra/compose/docker-compose.yml
COMPOSE_SANDBOX := docker compose \
  -f infra/compose/docker-compose.yml \
  -f infra/compose/docker-compose.sandbox.yml

.PHONY: up down logs seed plan wipe build test ps \
        hackathon sandbox-up sandbox-down sandbox-seed sandbox-pentest \
        sandbox-status doctor

build:
	$(COMPOSE) build --pull

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

wipe:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

seed:
	$(COMPOSE) exec tg-api python -m trustgraph_security.seed

plan:
	@JWT=$$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
	  -d "username=$$ADMIN_EMAIL&password=$$ADMIN_PASSWORD" | jq -r .access_token); \
	curl -s -X POST http://localhost:8000/api/v1/plan \
	  -H "Authorization: Bearer $$JWT" | jq '.tasks[:5]'

test:
	cd apps/api && PYTHONPATH=. pytest tests/ -q

# ─────────────── HACKATHON SANDBOX ─────────────────────────
# One-liner for a live demo. Builds, starts, seeds, runs one AI
# pentest, and opens the browser. ~3-5 min on a fresh laptop.
hackathon: doctor sandbox-up sandbox-seed sandbox-pentest
	@echo
	@echo "✅  Sandbox is live."
	@echo "   UI:        http://localhost:8080  (demo / demo)"
	@echo "   API docs:  http://localhost:8000/docs"
	@echo "   trustgraph http://localhost:8088"
	@command -v open >/dev/null && open http://localhost:8080 || \
	  command -v xdg-open >/dev/null && xdg-open http://localhost:8080 || true

doctor:
	@echo "🔎  Preflight…"
	@command -v docker >/dev/null || { echo '❌ docker not installed'; exit 1; }
	@docker compose version >/dev/null || { echo '❌ docker compose v2 required'; exit 1; }
	@test -f .env || cp .env.example .env
	@echo "   ✓ docker present"
	@echo "   ✓ .env present"

sandbox-up:
	@echo "🚀  Building + starting sandbox stack (this takes a few minutes the first time)…"
	$(COMPOSE_SANDBOX) up -d --build
	@echo "⏳  Waiting for trustgraph to become healthy…"
	@for i in $$(seq 1 60); do \
	  status=$$(docker inspect -f '{{.State.Health.Status}}' \
	    $$($(COMPOSE_SANDBOX) ps -q trustgraph) 2>/dev/null); \
	  if [ "$$status" = "healthy" ]; then echo "   ✓ trustgraph healthy"; break; fi; \
	  printf "."; sleep 5; \
	  if [ $$i -eq 60 ]; then echo; echo '❌ trustgraph never became healthy'; exit 1; fi; \
	done

sandbox-seed:
	@echo "📥  Loading payments-platform sandbox threat model…"
	$(COMPOSE_SANDBOX) exec -T tg-api python -m trustgraph_security.seed_sandbox

sandbox-pentest:
	@echo "🤖  Dispatching first AI pentest (this can take 1-3 min)…"
	@JWT=$$(curl -sf -X POST http://localhost:8000/api/v1/auth/login \
	  -d "username=demo@trustgraph.local&password=demo" | jq -r .access_token); \
	TOP=$$(curl -sf -X POST http://localhost:8000/api/v1/plan \
	  -H "Authorization: Bearer $$JWT" | jq -r '.tasks[0].id'); \
	echo "   top task: $$TOP"; \
	curl -sf -X POST "http://localhost:8000/api/v1/plan/tasks/$$TOP/execute" \
	  -H "Authorization: Bearer $$JWT" | jq .

sandbox-status:
	@$(COMPOSE_SANDBOX) ps

sandbox-down:
	$(COMPOSE_SANDBOX) down

sandbox-wipe:
	$(COMPOSE_SANDBOX) down -v
