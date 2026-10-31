# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — A6.3m.3b личная MFA операторов

[Контракт](../features/mfa-policy.md#личная-mfa-операторов--a63m3b). Server-only NewPlatform MFA repository закрепляет administrative=true для Status/Disable. Assembly выбирает его только платформе, standalone/project constructors прежние. Platform-only actor без Auth-admin роли не обходит administrators/required policy, optional не отменяет required role. Operator DELETE TOTP использует прежние fresh proofs/Access lock/cascade/auth_version/revoke/audit. Proof/HTTP DTO без нового флага; no deps/ENV/schema/workers.

Luna V1/V2/V3 PASS: API/Go tests/router unit, pinned lint0, targeted race, full schema/platform operators, platform-management/optional-last-admin SQL и полный operator HTTPS. HTTPS покрывает recovery StepUp/rotation/replay, optional disable/password-only login, voluntary enrollment start, required limited enrollment/confirmation без session и повторный MFA login. Production/Swagger после V1 не менялись. Fixture corrections: unsupported POST405, допустимый порядок proof timestamps, single prepared Exec, изоляция одного scoped login:factor-user budget в начале отдельного scenario на эксклюзивнойDB15 без изменения production5/min. Подробные первые FAIL/tool-block в history.

Snapshot `/private/tmp/auth-platform-personal-mfa-v3.daz256tv`, base `c04bffbe55db45f6a90051ab4a68bd4217915d69`, manifest17/metadata рядом. Все17 hashes совпали после проверок и с main перед обновлением статусов документации. Fixtures очищены. Последний pinned lint `/private/tmp/auth-platform-personal-mfa-v3-lint-pinned.log`/`.exit` PASS0. Пользователь разрешил коммит после PASS, факт проверять Git.

## Следующий шаг

Сверить оставшуюся platform/project MFA matrix и A6.3m.6 email/Telegram second factors (не реализованы), без повторов уже принятых TOTP/recovery gates. MP5/MP6R security/refactor/MP7/MP8 ресурсы/двухпроектная приёмка отдельно. UI только после предупреждения и отдельного согласования; внешние OAuth/SMTP, GC/maxRPS не закрыты.

## Процесс

Researcher Luna medium `01a18e7d-c688-7ad1-adde-123d62863064`. Executable checks только чат «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local/exact snapshot; старый checkout6377 не использовать. Cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:12`. Main не повторяет проверки и не ждёт полный прогон.

Pinned lint через `/Users/inforberi/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.darwin-arm64/bin/go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0`; GOPROXY=file:///Users/inforberi/go/pkg/mod/cache/download, cachedtool при sumdbmetadata GOSUMDB=off без редактирования deps. Старый installed golangci непригоден. Own LinuxARM64 PG18.6/Redis8.2/readonly /src/TLS SAN127/SCRAM; RedisDB15. Schema auth_schema_test DB/role/env AUTH_SCHEMA_TEST_DATABASE_URL/cwd package; platform auth_platform_test/userauth/AUTH_PLATFORM_TEST_DATABASE_URL/cwd migrations/platform; app AUTH_OPERATOR_TEST_DATABASE_URL/REDIS_ADDR/ROOT=/src. Только own fixtures; realENV/DB/staging не трогать. Новые dependencies требуют согласования.
