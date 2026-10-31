# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). Git/staging проверять по факту.

## Завершённый блок — A6.3m.5e, два проекта через HTTPS

Самостоятельный TestTwoProjectHTTPIsolationSQL подготавливает A/B штатными schema/secrets/SCRAM/managed командами и activation, последовательно освобождая preparation connection/DDL lock. Настоящие RuntimeCredentialReader/Registry/NewProjectHTTP/ProjectProfile обслуживают оба. HTTPS matrix проверяет cookie/MFA/Origin/CORS/CSRF/host/forwarded/plaintext denial, suspended A при доступном B, неизменность platform Auth/authority и одну сборку resident profile на проект. [Границы](../features/mfa-policy.md#два-проекта-через-https--a63m5e).

Luna V2 PASS: task check и exact SQL/HTTPS test с race/count1 на LinuxARM64/TLS/SCRAM. Manifest11 совпал до/после, все5 Go-файлов совпали с main перед коммитом. DB/roles A/B, own schemas/fixture roles удалены; RedisDB15 пуст. V1 был ошибочно вложен в старый onboarding drill, который удерживал DDL lock A: hook удалён, старый runtime_registry файл вернулся к HEAD, V2 независим. Production locks/API/schema/dependencies/ENV продукта не менялись; formatter выполнен. Подробности/первый FAIL в history.

Snapshot `/private/tmp/auth-two-project-https-v2.ugnwfmas`, base `a539fdb38492d16c1650cd190400286e8fb5545f`, parentV1, manifest11/metadata рядом; логи/exit-коды `/private/tmp/auth-two-project-https-v2-*`. Пользователь разрешил коммит после PASS; факт смотреть Git.

## Следующий шаг и границы

Сверить оставшиеся MP5 flows с фактической evidence, не повторять закрытые 5b–5e suites без причины. Ready/suspend seeded в catalogue: lifecycle command permissions/audit/final publication не проверяются этим тестом. Trusted profile source вместо manifest loader (отдельные tests). Ручные cookies/TLS client не заменяют browser jar/DNS/external reverse proxy/fleet. Полный MP5, providers/SMTP, A6.3m.6 email/Telegram second factors, MP6R security/refactor и MP7/MP8 ресурсы/maxRPS остаются открытыми. UI только после предупреждения и отдельного согласования.

## Исполнители и стенд

Все исполняемые проверки — только чат «Проверки Auth — Luna» `01a16eab-c777-78a0-a815-47b45ff0860d`, host local; main не повторяет их и не ждёт полный прогон. Последний cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:22`. Локальный read-only researcher завершил review и закрыт.

Pinned lint: cached Go1.27.3 + `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0`, GOPROXY=file:///Users/inforberi/go/pkg/mod/cache/download, при cached metadata GOSUMDB=off. Installed старый lint не подходит. Целевой SQL test ^TestTwoProjectHTTPIsolationSQL$; старый TestPrepareCommandSQL не нужен для его setup. Own LinuxARM64 PG18.6/Redis8.2/TLS SAN127/SCRAM/readonly /src. AUTH_PREPARE_TEST_CATALOG_URL ownauth_prepare_catalog_test, AUTH_STORAGE_TEST_DATABASE_URL ownauth_storage_test, AUTH_STORAGE_TEST_ROOT=/src, AUTH_STORAGE_TEST_TLS_CA=<ownCA>, AUTH_STORAGE_TEST_SCRAM_HOST=127.0.0.1, AUTH_PROJECT_PASSWORD_TEST_REDIS_ADDR=127.0.0.1:6379/DB15empty. A/B IDs ...0001 и ...0088; cleanup только own authp/autho/authr, schemas/catalog/journal/events и exact Redis keys без scan/FLUSHDB. Реальные ENV/DB/staging не трогать.
