.PHONY: help-swagger swagger

help-swagger:
	@echo ""
	@echo "Доступные команды:"
	@echo ""
	@echo "make swagger - Генерировать Swagger"
	@echo ""

swagger:
	go run github.com/swaggo/swag/cmd/swag@v1.16.6 init -g cmd/auth/main.go

	