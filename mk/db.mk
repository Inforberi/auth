.PHONY: help-db db-backup db-restore db-restore-replace db-shell

BACKUP_DIR=$(PROJECT_ROOT)/out/backups

DB_CONTAINER=$(POSTGRES_DB)
DB_USER=$(POSTGRES_USER)
DB_PASSWORD=$(POSTGRES_PASSWORD)

BACKUP_FILE=$(BACKUP_DIR)/$(DB_CONTAINER)_$(shell date +%d-%m-%Y_%H-%M-%S).sql

help-db:
	@echo ""
	@echo "Доступные команды:"
	@echo ""
	@echo "  db-backup            Создать бэкап базы в $(BACKUP_DIR)"
	@echo "  db-restore           Восстановить базу из файла (file=...)"
	@echo "  db-restore-replace   Полностью очистить базу и восстановить из файла (file=...)"
	@echo "  db-shell             Открыть psql внутри контейнера"
	@echo ""

db-backup:
	@mkdir -p $(BACKUP_DIR)
	$(COMPOSE) exec -T $(DB_CONTAINER) pg_dump -U $(DB_USER) $(DB_CONTAINER) > $(BACKUP_FILE)
	@echo "Backup saved to $(BACKUP_FILE)"

db-restore: ## Восстановить базу из файла
ifndef file
	$(error Укажи файл: make db-restore file=backups/backup.sql)
endif
	$(COMPOSE) exec -T $(DB_CONTAINER) psql -U $(DB_USER) $(DB_CONTAINER) < $(file)

db-restore-replace: ## Полная замена базы
ifndef file
	$(error Укажи файл: make db-restore-replace file=backups/backup.sql)
endif
	@$(COMPOSE) exec -T $(DB_CONTAINER) psql -U $(DB_USER) $(DB_CONTAINER) -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@$(COMPOSE) exec -T $(DB_CONTAINER) psql -U $(DB_USER) $(DB_CONTAINER) < $(file)

db-shell: ## Открыть psql
	@$(COMPOSE) exec $(DB_CONTAINER) psql -U $(DB_USER) $(DB_CONTAINER)