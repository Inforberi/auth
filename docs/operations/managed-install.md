# Управляемая установка на одном хосте

Первый блок создаёт локальный комплект для новой standalone-установки с отдельным Compose project name. Нужны доверенный Docker-хост, HTTPS ingress и SMTP relay с TLS, который принимает отправку из этой сети без логина. Первый владелец подтверждает почту и TOTP через существующий защищённый setup. Публичная регистрация при первом запуске закрыта.

Из корня репозитория выполните, заменив каталоги, домен и SMTP:

```sh
bundle="$HOME/auth-installation"
go run ./cmd/auth-install -dir "$bundle" -name auth-managed \
  -origin https://auth.example.org -smtp-host smtp.example.org \
  -smtp-from auth@example.org
```

Каталог должен находиться вне репозитория и быть недоступен другим пользователям. Установщик создаёт его с правами 0700, файлы публикует с 0600 без перезаписи. Повтор с теми же параметрами использует тот же комплект. Незавершённый комплект требует проверки и восстановления, прежде чем запускать сервис. До старта сохраните защищённую копию всего комплекта отдельно от хоста.

Для нового Compose проекта выполните этапы последовательно. Каталог для read-only mount должен существовать. HTTPS ingress направляется на loopback API. PostgreSQL и Redis работают внутри сети Compose.

```sh
mkdir -m 700 "$bundle/secrets"
export AUTH_SECRETS_DIR="$bundle/secrets"
export APP_ENV_FILE="$bundle/runtime.env"
compose() {
  docker compose --project-directory . --env-file "$bundle/storage.env" \
    -f deploy/compose/base.yml -f deploy/compose/production.yml "$@"
}
compose up -d --wait postgres redis
compose run --rm migrate up
compose exec -T postgres psql -v ON_ERROR_STOP=1 -U auth_owner -d auth \
  < "$bundle/runtime-role.sql"
compose exec -T postgres psql -v ON_ERROR_STOP=1 -U auth_owner -d auth \
  < internal/admin/projects/schema/runtime-grants.sql
compose up -d --build api backup
```

Runtime получает пароль ограниченной роли, Redis, ключ шифрования и setup-токен. Пароль владельца БД находится в отдельном эксплуатационном файле. Docker administrator имеет доступ к окружению контейнеров. Токен из приватного комплекта передаётся только в защищённый setup по инструкции. [Первый владелец](../features/initial-setup.md)

Если панель недоступна, восстановите комплект из защищённой копии с прежними именем проекта, паролями и ключом. После восстановления БД следуйте штатному порядку применения grants, сверки прав и отзыва доступа перед открытием трафика. Повторная генерация создаст другой ключ и не расшифрует прежние данные. [Руководство по восстановлению](jwt-recovery.md)

Этот этап рассчитан на новую standalone-установку. Подключение существующих БД, установка platform/multi-project, ротация ключей и автоматический recovery остаются отдельными работами. Luna подтвердила проверку комплекта, закрытый профиль, раздельные credentials и ограниченную роль PostgreSQL на изолированном стенде. Финальный прогон подтвердил тесты, линтер и путь Compose к миграциям. Стенд переиспользован. Доставка через реальный SMTP и вход первого владельца не проверялись. Отчёты находятся в /private/tmp/auth-install-check-sCODdG/summary.json и /private/tmp/auth-install-recheck-ZfSGhn/receipt.json.
