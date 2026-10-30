# Текущий шаг

Обновлено 30 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — A6.3m.5a MFA capability compatibility

[Контракт](../features/mfa-policy.md#совместимость-capability--a63m5a). CheckCapability/CheckDisabled валидируют policy singleton и совместимость engine с enrolled factors, required roles и realm/admin requirements. BuildProjectProfile/assessment проверяет выбранную БД до сборки компонентов; новых login round trips нет. Platform/setup engine=true сохранён, optional не требует личного enrollment. Закрытый профиль без primary-конфигурации валидирует policy, не требует login capability. Финальные SQL/session guards не менялись. Новых deps/ENV/schema/routes/Swagger/workers нет.

Luna V1 task check/race/full command SQL/capability+isolation/platform operators/operator HTTPS PASS. V2 исправил fixture last-admin (не выдавать super_admin вспомогательным actors) и ожидание401 при NULL-MFA session; targeted lint/race/optional-last-admin PASS. V3 исправил реальный Access recordAudit []byte→string JSON parameter в simple protocol. Targeted lint0/race, TestAdministratorAssignmentsSchema и полный TestPostgresSchema PASS раздельными протокольными прогонами; подробности/первые FAIL/ограничения в history. Fixtures очищены. Snapshot `/private/tmp/auth-mfa-capability-v3.3kp_jtfb`, base `34db845656956ade1f4d23ed7a7d9106ee6ac6ad`, manifest12/metadata рядом, все12 hashes совпали с main перед обновлением статусов документов. Пользователь разрешил коммит после PASS; факт проверять Git.

## Следующий шаг

Protected MFA settings HTTP и оставшаяся optional platform/project matrix. MP5/MP6R security/refactor/MP7/MP8 ресурсы и полная двухпроектная приёмка отдельно. UI только после предупреждения и отдельного согласования. Внешние OAuth/SMTP, GC/maxRPS не закрыты. Общий JWT simple-protocol compatibility этим блоком не заявлен.

## Процесс и evidence

Researcher Luna medium `01a183e1-ca25-7972-a67a-eadef20a0b41`, переиспользовать. Executable checks только чат «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local/exact snapshot; checkout6377/auth устарел. Cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:4`. Main не дублирует и не ждёт полный прогон.

Own LinuxARM64 PG18.6/readonly /src, socket trust/TCP127 SCRAM wrongpwdeny/TLS SAN127; Redis8.2 PGnetwork127/DB15. Command mandatory SCRAM_HOST/TLS_CA/ROOT=/src/Redis127. Schema auth_schema_test DB/role/env AUTH_SCHEMA_TEST_DATABASE_URL/cwd package; platform auth_platform_test/user auth/env AUTH_PLATFORM_TEST_DATABASE_URL/cwd migrations/platform; app AUTH_OPERATOR_TEST_DATABASE_URL/REDIS_ADDR/ROOT=/src. Pinned lint2.14.0/Go1.27.3 cached modules /Users/inforberi/go/pkg/mod, offline GOPROXY file cache. Только own fixtures, realENV/DB/staging не трогать. Новые зависимости требуют согласования.
