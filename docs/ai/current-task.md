# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). Git/staging проверять по факту.

## Завершённый блок — A6.3m.5c native/JWT MFA matrix

Добавлены и проверены TestMFAPolicyNativeSchema (password/email OTP × realm/role, optional credentials, required enrollment без credentials, реальные TOTP enrollment/recovery completion, JWT claims/refresh/introspection и отсутствие revival) и TestMFAPolicyJWTConsumersSchema (primary-only/personal MFA × realm/role, browser exchange/online introspection, старые sessions после tighten/relax, новый login и offline TTL). [Контракт](../features/mfa-policy.md#native-и-jwt--a63m5c).

Production/API/schema/ENV/dependencies без изменений. Formatter выполнен. Снимок `/private/tmp/auth-mfa-native-jwt-v1.kbrq7ko3` (base `5f9ac6c0a0a37bb8a3a96ece4948ceb8728cb54e`, manifest6/metadata рядом) передан Luna на task check/fullGo/pinned lint и два новых SQL tests с race/count1 без SKIP. Luna V1 PASS: task check и оба SQL tests с race на LinuxARM64/TLS/SCRAM без SKIP. Manifest6 совпал до/после, оба Go-файла совпали с main, own fixture удалён. Логи/exit-коды `/private/tmp/auth-mfa-native-jwt-v1-*`. Пользователь разрешил коммит после PASS; факт смотреть Git. Предыдущий блок A6.3m.5b принят Luna V1/V2 и закоммичен в 5f9ac6c; повторять его проверки без причины не нужно.

## Следующий шаг

Полная двухпроектная приёмка остаётся открытой. A6.3m.6 email/Telegram **second factors** ещё не реализованы. MP6R security/refactor, MP7/MP8 ресурсы/maxRPS и внешние OAuth/SMTP не закрыты. UI только после предупреждения и отдельного согласования.

## Исполнители

Все исполняемые проверки — только чат «Проверки Auth — Luna» `01a16eab-c777-78a0-a815-47b45ff0860d`, host local; main не повторяет их и не ждёт полный прогон. Последний cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:16`. Локальный исследователь завершил bounded review и закрыт; старых агентов не восстанавливать.

Pinned lint: Go1.27.3 из cached toolchain + `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0`; GOPROXY=file:///Users/inforberi/go/pkg/mod/cache/download, при cached metadata GOSUMDB=off без изменения deps. Installed старый lint не подходит. SQL: только own LinuxARM64 PG18.6/Redis8.2/readonly snapshot, TLS SAN127/SCRAM, role/DB auth_schema_test, AUTH_SCHEMA_TEST_DATABASE_URL/cwd password repo; cleanup только own fixtures. Реальные ENV/DB/staging не трогать.
