.PHONY: dev-up dev-up-build dev-down dev-clean-up dev-db-up dev-db-down dev-logs-app

DEV_SERVICES=finance-db postgres-port-forwarder

docker-dev-help:
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


dev-up-app:
	go run $(FINANCE_APP_LOCATION)

dev-up-build:
	$(COMPOSE) up -d --build $(DEV_SERVICES)
	go run $(FINANCE_APP_LOCATION)

dev-down:
	$(COMPOSE) down --remove-orphans

dev-db-up:
	$(COMPOSE) up -d finance-db postgres-port-forwarder

dev-db-down:
	$(COMPOSE) stop finance-db postgres-port-forwarder

dev-clean-up:
	@read -p "Очистить локальные данные БД? [y/N]: " ans; \
	if [ "$$ans" = "y" ] || [ "$$ans" = "Y" ]; then \
		docker compose down && rm -rf out/pgdata && echo "Данные очищены"; \
	else \
		echo "Отменено"; \
	fi

dev-logs-app:
	$(COMPOSE) logs -f finance-app --tail=100