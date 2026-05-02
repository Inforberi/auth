include .env
export

export PROJECT_ROOT=$(shell pwd)
export PROJECT_ROOT

COMPOSE=docker compose -f $(PROJECT_ROOT)/deploy/docker-compose.yml
FINANCE_APP_LOCATION=$(PROJECT_ROOT)/cmd/finance-app/main.go

.PHONY: help

help:
	@echo ""
	@echo "Доступные команды:"
	@echo ""
	@echo "make docker-dev-help - Узнать доступные команды запуска проекта в режиме разработки"
	@echo "make migrate-help - Узнать доступные команды миграций"
	@echo "make docker-prod-help - Узнать доступные команды запуска проекта в режиме production"
	@echo "make db-help - Узнать доступные команды работы с Базой Данных"

include mk/docker-dev.mk
include mk/docker-prod.mk
include mk/migrate.mk
include mk/db.mk