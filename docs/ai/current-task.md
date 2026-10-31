# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). Git/staging проверять по факту.

## Завершённый блок — A6.3m.5d component realm isolation

TestMFAProjectIsolationSQL проверяет две реальные project Auth БД + platform Auth БД с отдельными SQL credentials, одинаковыми user UUID/email/root key, scoped crypto и независимыми JWT keys/issuers при одном kid. Cross-realm session/exchange/JWT/introspection/refresh/MFA challenge и чужой SQL login отвергаются. Policy/role/enrollment/recovery/Disable в A не меняют полный state digest B/platform; их sessions/JWT/refresh сохраняются. Реальный общий Redis проверяет независимые scoped project/user MFA budgets. [Границы](../features/mfa-policy.md#межпроектная-изоляция--a63m5d).

Luna V1/V2/V3 PASS: fullGo и JWT SQL regression, exact isolation SQL race/count1, финальный pinned lint0. Исправлены только fixtures: ctx через helpers и отдельная ConfirmPassword/cookie rotation после MFA completion перед Disable. Production/API/schema/ENV продукта/dependencies прежние. Formatter выполнен; все3 Go-файла совпали с V3 перед коммитом. Own3DB/roles удалены, RedisDB15 пуст. Подробные первые FAIL/evidence в history.

V3 `/private/tmp/auth-mfa-realm-isolation-v3.jou1lmaw`, parentV2 `/private/tmp/auth-mfa-realm-isolation-v2.fcjo_b8t`, base `c54b2f36542e2e5daac89551c0b6dc7b3a565c7e`, manifest9/metadata рядом. Логи/exit-коды `/private/tmp/auth-mfa-realm-isolation-v{1,2,3}-*`. Пользователь разрешил коммит после PASS; факт смотреть Git.

## Следующий шаг

Полная MP5 остаётся открытой: actual ProjectProfile/registry/provisioner и HTTPS cookies/ingress/CSRF/Origin, operator bridge, providers/SMTP и прочие flows — отдельные gates; component PASS их не заменяет. A6.3m.6 email/Telegram second factors ещё не реализованы. MP6R security/refactor, MP7/MP8 ресурсы/maxRPS не закрыты. UI только после предупреждения и отдельного согласования.

## Исполнители и стенд

Все исполняемые проверки — только чат «Проверки Auth — Luna» `01a16eab-c777-78a0-a815-47b45ff0860d`, host local; main не повторяет их и не ждёт полный прогон. Последний cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:20`. Локальный read-only researcher завершил review и закрыт; старых агентов не восстанавливать.

Pinned lint: cached Go1.27.3 + `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0`, GOPROXY=file:///Users/inforberi/go/pkg/mod/cache/download, при cached metadata GOSUMDB=off. Installed старый lint не подходит. Test ENV AUTH_MFA_ISOLATION_TEST_DATABASE_URL: own LinuxARM64 PG18.6/TLS/SCRAM, loopback127/databaseauth_storage_test/userauth, CREATE ROLE/DATABASE для fixed disposable ресурсов auth_mfa_isolation_{a,b,platform}_test. Fixture требует отсутствия, создаёт отдельных owners, cleanup только own databases/roles. Own Redis8.2 DB15 пуст; AUTH_PROJECT_PASSWORD_TEST_REDIS_ADDR, точный cleanup без scan/FLUSHDB. Реальные ENV/DB/staging не трогать.
