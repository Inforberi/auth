include .env
export

export PROJECT_ROOT=$(shell pwd)
export PROJECT_ROOT

COMPOSE=docker compose -f $(PROJECT_ROOT)/deploy/docker-compose.yml
APP_LOCATION=$(PROJECT_ROOT)/cmd/auth
APP_CONTAINER=auth-app
DB_CONTAINER=auth-db

.PHONY: help

help:
	@echo ""
	@echo "Доступные команды:"
	@echo ""
	@echo "make help-dev - Узнать доступные команды запуска проекта в режиме разработки"
	@echo "make help-migrate - Узнать доступные команды миграций"
	@echo "make help-prod - Узнать доступные команды запуска проекта в режиме production"
	@echo "make help-db - Узнать доступные команды работы с Базой Данных"

include mk/dev.mk
include mk/prod.mk
include mk/migrate.mk
include mk/db.mk