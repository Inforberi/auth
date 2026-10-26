# Текущий шаг

Обновлено 26 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1i project identity management

[Контракт](../features/project-identity-management.md). Четыре project Google/Telegram POST/DELETE link routes на existing OIDC services/SQL. Exact Origin/NoRefresh/current key; method-qualified handler key приоритетнее shared path binding. Сохранён строгий verified permanent password + fresh password proof контракт; не обещать Google+Telegram/OTP-only unlink без пароля. Callback shared purpose/state/browser binding/provider revision/issuer+subject/no merge прежние, link не выдаёт session.

Закрыт найденный SQL fallback gap: unlink требует password_enabled под policy FOR SHARE доcommit, не только наличие hash. HTTP дополнительно требует готовый password feature (другая гарантия). Transactional remove/version/revoke/audit прежние. Новых deps/ENV/schema/workers нет.

Main formatter/source/read-only review; lock-order cycle не найден. V1 Luna taskcheck/API/security/race/TestPostgresSchema identity_management PASS. Исправлен только synthetic sessionINSERT (обязательныеuser_agent/ip_address). V2 targeted lint0/full TestPrepareCommandSQL PASS; новый project_identity_HTTP без skips. Все10source hashes совпали после прогона и с main; свои containers/network/build files очищены.

Snapshot `/private/tmp/auth-project-identity-management-v2.x4wnb8t9`, manifest sameprefix-manifest.sha256, metadata sameprefix-snapshot.json. Evidence history, logs `/private/tmp/auth-project-identity-management-v2-*.log`. Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:5. Пользователь разрешил коммит; факт проверять Git.

## Следующий шаг

После приёмки — MFA management HTTP и оставшиеся account administrative consumers по MP5, полная two-project matrix/phase-ready. Rotation/retention/fleet/MP6R/MP7/MP8 отдельно. External provider/SMTP/DNS/TLS/GC/RPS не считать закрытыми. UI только после предупреждения и отдельного согласования.

## Процесс

- Read-only researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2, gpt-6-luna medium/reuse.
- Все executable checks только Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- SQL command: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAMwrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory; не macHost/randomport/trustTCP. Shared repo regression: только fresh auth_schema_test/role auth_schema_test, AUTH_SCHEMA_TEST_DATABASE_URL TCP127; targeted TestPostgresSchema/identity_management. Толькоownfixturecleanup.
- Govulncheck ранее0reachable,1required-module advisory внеimport/callgraph; уточнить приMP6R, не обновлятьdepsбезразрешения.
- Real ENV/secrets/БД/staging сохранять. Commit только по запросу. Full MP5/MP7/MP8/UI gates открыты.
