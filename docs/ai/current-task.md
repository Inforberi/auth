# Текущий шаг

Обновлено 30 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — A6.3m.2b first-run выбор MFA

[Контракт setup](../features/initial-setup.md), [MFA policy](../features/mfa-policy.md#первый-запуск--a63m2b). Start с installation operator proof принимает mfaMode optional/administrators/required, default administrators. Mode закреплён в encrypted intent; старые intents требуют прежний TOTP. Completion не принимает mode и не выдаёт session. Optional не создаёт factor/recovery/audit enrollment; required/admin требуют TOTP. Setup owner, существующий policy writer/version/audit, platform permissions и markers — одна транзакция. Technical MFA capability пока обязательна; новых deps/ENV/миграций/workers нет.

Luna V1: Go tests/API, account race, SQL setup all3modes + legacy concurrency/policy regressions, platform setup/rollback/authority и operator HTTPS PASS. Единственный FAIL lint cyclop21 исправлен переносом согласованности режима/фактора в domain.SetupAccount.MFAPolicy без изменения правил. V2 targeted lint/race и affected standalone/platform setup SQL PASS без пропусков; fixtures очищены. Snapshot `/private/tmp/auth-mfa-setup-choice-v2.a2at9ljg`, base `50a53e0f943425e9a5987de2c419d9daddcb43fc`, manifest20/metadata рядом; все20 hashes совпали с main перед обновлением статусов документации. Evidence в history. Коммит разрешён пользователем после PASS; факт проверять Git.

## Следующий шаг

Platform/project capability/readiness matrix, затем protected settings HTTP. Полный optional profile ещё не принят; MP5/MP6R security/refactor/MP7/MP8 ресурсные прогоны отдельно. UI только после предупреждения и отдельного согласования. Внешние OAuth/SMTP, GC/maxRPS не закрыты.

## Процесс и evidence

Read-only researcher Luna medium `01a183e1-ca25-7972-a67a-eadef20a0b41`, переиспользовать; основные source/SQL проверяет main. Executable checks только чат «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local/exact snapshot; checkout6377/auth устарел. Последний cursor `19bf04ec-f4f6-4693-9c20-73f414b172e4:30`. Main не дублирует и не ждёт полный прогон.

Own LinuxARM64 PG18.6/readonly /src, socket trust/TCP127 SCRAM wrongpwdeny/TLS SAN127; Redis8.2 PGnetwork127/DB15. Schema auth_schema_test DB/role/env AUTH_SCHEMA_TEST_DATABASE_URL/cwd package; platform auth_platform_test/user auth/env AUTH_PLATFORM_TEST_DATABASE_URL/cwd migrations/platform; app AUTH_OPERATOR_TEST_DATABASE_URL/REDIS_ADDR/ROOT=/src. Pinned lint2.14.0/Go1.27.3 cached toolchain/modules /Users/inforberi/go/pkg/mod; offline GOPROXY file cache. Только own fixtures, realENV/DB/staging не трогать. Новые зависимости требуют согласования.
