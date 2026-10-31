# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [MP5](../planning/multi-project.md#сессии-и-почта-двух-проектов--mp5-sessions-email). Git/staging проверять по факту.

## Завершён MP5-sessions-email — Luna V1/V2 PASS

TestTwoProjectSessionLifecycleIsolationSQL: actual HTTPS login/reauthentication, foreign cookie/session IDs, list/revoke/rotate/logout/logout-all, account block/unblock/delete A без повреждения B, stale/tombstone retries. TestTwoProjectEmailIsolationSQL: настоящие component ProjectEmail/ProjectPassword A/B, scoped payload/cipher, verify/reset/invite/temporary/change/report/recovery cross-token/one-time guards, independent UUIDs, own revocation и B unchanged. Раздельные SMTP settings/from/credentials/listeners; существующий scheduler и TLS-required rejection → независимые outbox retries. SQL-seeded component proofs не считаются проверкой login, successful delivery или email HTTP/browser matrix.

V1 task check и Email root race PASS; V2 targeted lint/SessionLifecycle root race/count1 PASS. Cleanup и manifest14 подтверждены Luna; main сверил все14 файлов с V2 до итогового обновления Markdown, Go не менялся. V1 fixture HTTP expectation401 исправлена на контрактный400 invalid_credentials без production/API изменений. Snapshot `/private/tmp/auth-two-project-sessions-email-v2.w8ce8ztd`, manifest/metadata рядом, base c9e5cfa182910cb628b350b27edc2677f49f4522; evidence `/private/tmp/auth-two-project-sessions-email-v1-*` и `v2-*`, подробности в history. Shared helpers/production/schema/ENV/dependencies прежние. Пользователь разрешил коммит после PASS. Исследователь закрыт, UI не начинался.

## Следующий блок

Два actual JWT/native/JWKS/introspection HTTP profiles, затем OIDC callbacks/state/PKCE/nonce. Directory/identity pending и полная email HTTP/browser matrix, public project lifecycle/fault/fleet остаются gates полной MP5. Далее A6.3m.6 email/Telegram second factors, backend templates, security/refactor и MP7/MP8 ресурсы/maxRPS. UI только после предупреждения и отдельного согласования.

## Проверки

Только чат «Проверки Auth — Luna» `01a16eab-c777-78a0-a815-47b45ff0860d`, host local, cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:28`. Main не запускает tests/lint/SQL и не ждёт полный прогон. Принятые проверки не повторять без изменения их гарантий. Pinned Go1.27.3/lint2.14.0; старый installed lint не подходит.

Two-project roots имеют independent setup, legacy TestPrepareCommandSQL не нужен. Own PG18.6/Redis8.2/TLS/SCRAM/readonly /src; disposable auth_prepare_catalog_test/auth_storage_test ENV, RedisDB15 exact-key cleanup. Реальные ENV/DB/staging не трогать.
