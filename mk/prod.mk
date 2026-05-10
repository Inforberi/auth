.PHONY: help-prod prod-up prod-up-app prod-down prod-logs-app prod-db-up prod-db-down

help-prod:
	@echo ""
	@echo "Доступные команды:"
	@echo ""
	@echo "make prod-up          - Запустить все сервисы"
	@echo "make prod-up-app      - Запустить только приложение"
	@echo "make prod-down        - Остановить и удалить контейнеры"
	@echo "make prod-logs-app    - Посмотреть логи приложения"
	@echo ""
	@echo "make prod-db-up       - Запустить только Postgres"
	@echo "make prod-db-down     - Остановить только Postgres"
	@echo ""

prod-up:
	$(COMPOSE) up -d --build $(APP_CONTAINER) $(DB_CONTAINER)

prod-up-app:
	$(COMPOSE) up -d --build $(APP_CONTAINER)

prod-db-up:
	$(COMPOSE) up -d $(DB_CONTAINER)

prod-db-down:
	$(COMPOSE) stop $(DB_CONTAINER)

prod-down:
	$(COMPOSE) down --remove-orphans

prod-logs-app:
	$(COMPOSE) logs -f $(APP_CONTAINER) --tail=100

