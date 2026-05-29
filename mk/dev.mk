.PHONY: help-dev dev-up dev-up-build dev-down dev-clean-up dev-db-up dev-db-down dev-logs-app dev-redis-up dev-redis-down

DEV_SERVICES=$(DB_CONTAINER) $(REDIS_CONTAINER) postgres-port-forwarder redis-port-forwarder

help-dev:
	@echo ""
	@echo "Доступные команды:"
	@echo ""
	@echo "make dev-up          - Запустить "
	@echo "make dev-up-build    - Запустить с пересборкой образов"
	@echo "make dev-down        - Остановить и удалить контейнеры"
	@echo "make dev-clean-up    - Удалить контейнеры и очистить данные БД"
	@echo "make dev-logs-app    - Посмотреть логи приложения"
	@echo ""
	@echo "make dev-db-up        - Запустить только Postgres и postgres-port-forwarder"
	@echo "make dev-db-down      - Остановить только Postgres и postgres-port-forwarder"
	@echo ""
	@echo "make dev-redis-up        - Запустить только Redis и redis-port-forwarder"
	@echo "make dev-redis-down      - Остановить только Redis и redis-port-forwarder"
	@echo ""


dev:
	go mod tidy
	make swagger
	$(COMPOSE) up -d --build $(DEV_SERVICES)
	go run $(APP_LOCATION)

dev-app:
	go run $(APP_LOCATION)

dev-down:
	$(COMPOSE) down --remove-orphans

dev-db-up:
	$(COMPOSE) up -d $(DB_CONTAINER) postgres-port-forwarder

dev-db-down:
	$(COMPOSE) stop $(DB_CONTAINER) postgres-port-forwarder

dev-redis-up:
	$(COMPOSE) up -d $(REDIS_CONTAINER) redis-port-forwarder

dev-redis-down:
	$(COMPOSE) stop $(REDIS_CONTAINER) redis-port-forwarder

dev-clean-up:
	@read -p "Очистить локальные данные БД? [y/N]: " ans; \
	if [ "$$ans" = "y" ] || [ "$$ans" = "Y" ]; then \
		docker compose down && rm -rf out/pgdata && echo "Данные очищены"; \
	else \
		echo "Отменено"; \
	fi

dev-logs-app:
	$(COMPOSE) logs -f $(APP_CONTAINER) --tail=100