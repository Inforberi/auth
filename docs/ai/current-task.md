# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [матрица MP5](../planning/multi-project.md#сверка-приёмки-mp5--31-октября-2026). Git/staging проверять по факту.

## Завершён MP5-access — Luna V4 PASS

TestTwoProjectAccessIsolationSQL: две реальные БД и reader/registry/HTTPS, admin accounts через login + password reauthentication, чужие sessions/IDs, независимые roles/access/settings versions, delegation/fresh/last-admin, immediate A session denial при действующей B. Platform bridge использует одну SQL-seeded fresh operator session для независимых A/B intents/receipts и wrong-project/replay guards. Production/schema/dependencies/ENV не менялись. Пользователь разрешил коммит после PASS.

V1 task check и прежний HTTPS root PASS. V4 targeted lint и Access root race/count1 PASS; cleanup и manifest13 подтверждены Luna. Main сверил все13 файлов с V4 до обновления итоговых Markdown; код не менялся. Исправления V1–V3 касались только fixture login endpoint, fresh password proof и FK cleanup; подробности/evidence в history. Snapshot `/private/tmp/auth-two-project-access-v4.w5uy676g`, manifest/metadata рядом; evidence `/private/tmp/auth-two-project-access-v4-*`, base `0ecdb84f4f059032d3bb5ceddd8150f2a0aae1f4`. Исследователь закрыт, UI не начинался.

## Следующий блок

Two-project session/lifecycle и email pending/outbox: отзыв в A при сохранении B, затем purpose-bound verify/reset/invite/temporary/change/report/recovery и delivery retries на существующей fixture. Далее actual JWT/native/JWKS/introspection HTTP profiles и OIDC callback/state/PKCE/nonce. Same-DB foreign manifest не считать двумя проектами. Полный MP5 открыт; A6.3m.6 email/Telegram second factors, backend email templates, security/refactor и MP7/MP8 ресурсы/maxRPS отдельно. UI только после предупреждения и отдельного согласования.

## Проверки

Чат «Проверки Auth — Luna»: `01a16eab-c777-78a0-a815-47b45ff0860d`, host local; последний cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:26`. Main не запускает tests/lint/SQL и не ждёт полный прогон. Принятые проверки не повторять без изменения их гарантий. Pinned Go1.27.3/lint2.14.0; старый installed lint не подходит.

Two-project roots имеют независимый setup, legacy TestPrepareCommandSQL не нужен. Own PG18.6/Redis8.2/TLS/SCRAM/readonly /src; disposable auth_prepare_catalog_test/auth_storage_test ENV, scoped RedisDB15 exact-key cleanup. Не трогать реальные ENV/DB/staging.
