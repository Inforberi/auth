.PHONY: help-migrate migrate-create migrate-up migrate-down

MIGRATE_CMD=docker compose run --rm postgres-migrate \
	-path /migrations \
	-database "postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@template-db:5432/${POSTGRES_DB}?sslmode=disable"

help-migrate:
	@echo ""
	@echo "Доступные команды:"
	@echo ""
	@echo "make migrate-create  - Создать новую миграцию"
	@echo "make migrate-up      - Применить миграции"
	@echo "make migrate-down    - Откатить миграции"
	@echo ""

migrate-create:
	@read -p "Введите название миграции: " seq; \
	if [ -z "$$seq" ]; then \
		echo "Имя миграции не может быть пустым"; \
		exit 1; \
	fi; \
	docker compose run --rm postgres-migrate \
	create \
	-ext sql \
	-dir /migrations \
	-seq "$$seq"


migrate-up:
	@read -p "Введите количество миграций [по умолчанию: все]: " steps; \
	if [ -n "$$steps" ] && ! echo "$$steps" | grep -Eq '^[0-9]+$$'; then \
		echo "Количество должно быть числом"; \
		exit 1; \
	fi; \
	$(MIGRATE_CMD) up $${steps:+$$steps}

migrate-down:
	@read -p "Введите количество миграций [по умолчанию: 1]: " steps; \
	if [ -z "$$steps" ]; then steps=1; fi; \
	if ! echo "$$steps" | grep -Eq '^[0-9]+$$'; then \
		echo "Количество должно быть числом"; \
		exit 1; \
	fi; \
	$(MIGRATE_CMD) down $$steps