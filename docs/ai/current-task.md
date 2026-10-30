# Текущий шаг

Обновлено 30 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — A6.3m.2c protected MFA settings HTTP

[Контракт](../features/mfa-policy.md#http-api-политики--a63m2c). Shared handler/DTO/error rules, standalone/project GET/POST `/api/v1/admin/auth/settings/mfa` с auth.settings.manage; platform GET/POST `/api/v1/platform/settings/mfa` с independent operator SettingsManage authority. Project manifest mfaSettings default-off, RoutePlan/browser binding, bounded lease/current-catalog guards. Existing SQL writer/version/audit/readiness/fresh proofs сохранены. Stronger policy возвращает committed snapshot200, следующая старая cookie401; повторного actor-check после commit нет. Новых deps/ENV/schema/workers нет.

Platform подключены limited login enrollment и authenticated TOTP enrollment start/confirm. DELETE platformTOTP, полный personal management/optional matrix и межпроектный MFA policy bridge отдельно. UI не начинался.

Luna V1 task check/API, targeted race, schema policy/runtime/capability и platform operators PASS. V2 operator HTTPS PASS, cleanup разделён на отдельные prepared Exec; project first404 явно сбрасывает stale route plan после preceding Auth fixture restore. V3 создаёт собственный ordinary user/session вместо отозванного bindingToken: targeted lint/race/full ARM64 command SQL/project MFA HTTPS PASS. Version/session_revision в cleanup не уменьшаются; тесты идут в конце parent. Manifest33 совпал после проверок и с main перед обновлением документационных статусов. Fixtures очищены. Snapshot `/private/tmp/auth-mfa-settings-http-v3.hp898zr2`, base `05865b3941855fb90bcbfdd560b3e15850f16a82`, manifest/metadata рядом. Первые FAIL и evidence в history. Коммит разрешён после PASS, факт проверять Git.

## Следующий шаг

Оставшаяся optional platform/project matrix: полный личный MFA management для операторов, required enrollment по реальному HTTP и transitions/recovery/last-admin для поддерживаемых сочетаний. MP5/MP6R security/refactor/MP7/MP8 ресурсы/двухпроектная приёмка отдельно. UI только после предупреждения и отдельного согласования. Внешние OAuth/SMTP, GC/maxRPS не закрыты.

## Процесс и evidence

Read-only researcher Luna medium `01a18e7d-c688-7ad1-adde-123d62863064`, переиспользовать; старый ID недоступен. Executable checks только чат «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local/exact snapshot; checkout6377/auth устарел. Cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:7`. Main не дублирует и не ждёт полный прогон.

Own LinuxARM64 PG18.6/readonly /src, socket trust/TCP127 SCRAM wrongpwdeny/TLS SAN127; Redis8.2 PGnetwork127/DB15. Command mandatory SCRAM_HOST/TLS_CA/ROOT=/src/Redis127. Schema auth_schema_test DB/role/env AUTH_SCHEMA_TEST_DATABASE_URL/cwd package; platform auth_platform_test/user auth/env AUTH_PLATFORM_TEST_DATABASE_URL/cwd migrations/platform; app AUTH_OPERATOR_TEST_DATABASE_URL/REDIS_ADDR/ROOT=/src. Pinned lint2.14.0/Go1.27.3 cached modules /Users/inforberi/go/pkg/mod, offline GOPROXY file cache. Только own fixtures, realENV/DB/staging не трогать. Новые зависимости требуют согласования.
