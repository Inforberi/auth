# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). Git/staging проверять по факту.

## Завершённый блок — A6.3m.5b матрица MFA и гонки отключения

SQL/coordinator matrix Google/Telegram/email OTP проверяет optional без фактора, required от роли/realm, enrollment и сохранение личного фактора после смягчения. Disable TOTP проверен против realm/role tightening: оба последовательных порядка и concurrent, конечная обязательность/factor/auth_version, отзыв старой сессии и отказ новой factorless session. Production/API/schema/ENV/dependencies без изменений. [Контракт и границы](../features/mfa-policy.md#дополнение-матрицы--a63m5b).

Luna V1/V2 PASS: task check/fullGo/pinned lint0, оба новых SQL tests с race/count3, три SQL regression. V1 primary matrix падала из-за повторного synthetic issuer+subject; V2 включил source в subject, повторил только affected SQL/race/lint. Formatter выполнен; оба Go-файла совпали с проверенным V2. Own fixtures очищены; подробности/первый FAIL в history.

V2 `/private/tmp/auth-mfa-policy-matrix-v2.8ljq3gtq`, parent `/private/tmp/auth-mfa-policy-matrix-v1.ifnt178v`, base `4a80e035f66b007b23181c7b05b65b9fc54eb2ee`, manifest5/metadata рядом. Логи/exit-коды `/private/tmp/auth-mfa-policy-matrix-v{1,2}-*`. Пользователь разрешил коммит после PASS; факт смотреть Git.

## Следующий шаг

Выделенная optional/required матрица native/JWT, затем полная двухпроектная приёмка остаются открытыми. A6.3m.6 email/Telegram **second factors** ещё не реализованы. MP6R security/refactor, MP7/MP8 ресурсы/maxRPS и внешние OAuth/SMTP не закрыты. UI только после предупреждения и отдельного согласования.

## Исполнители

Локальные исследователи закрыты по запросу пользователя. Все исполняемые проверки — только чат «Проверки Auth — Luna» `01a16eab-c777-78a0-a815-47b45ff0860d`, host local; main не повторяет их и не ждёт полный прогон. Последний cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:15`.

Pinned lint: Go1.27.3 из cached toolchain + `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0`; GOPROXY=file:///Users/inforberi/go/pkg/mod/cache/download, при cached metadata GOSUMDB=off без изменения deps. Installed старый lint не подходит. SQL: только own LinuxARM64 PG18.6/Redis8.2/readonly snapshot, TLS SAN127/SCRAM, role/DB auth_schema_test, AUTH_SCHEMA_TEST_DATABASE_URL; cleanup только own fixtures. Реальные ENV/DB/staging не трогать.
