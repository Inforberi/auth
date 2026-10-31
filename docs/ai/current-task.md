# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [MP5-token-http](../planning/multi-project.md#jwt-и-native-двух-проектов--mp5-token-http). Git/staging проверять по факту.

## Завершён MP5-token-http — Luna V1 PASS

TestTwoProjectTokenIsolationSQL использует прежние prepareHTTPProjects/newProjectIsolationHTTP и два настоящих HTTP profiles с own origins/issuer/prepared keys/client secrets; одинаковые user UUID/email/audience/client ID, разные DB names/OID. Browser exchange, JWKS cache/ETag/signature/issuer, чужие cookies/clients/tokens, introspection inactive/audience scope, native password/refresh/replay/logout и logout-all A при действующем B. Foreign well-formed logout204 без эффекта — прежний контракт. Offline signature после online revoke остаётся валидной до TTL, не заменяет strict authority.

Production/shared helpers/schema/ENV/deps прежние. Formatter/source review выполнены; main tests/lint/SQL не запускал, researcher закрыт. Cleanup удаляет свои audits/refresh rows/role assignments и точные scoped Redis keys, включая session IDs перед удалением sessions. Luna V1: task check и TestTwoProjectTokenIsolationSQL race/count1 PASS, fixture cleanup и manifest11 подтверждены. Main сверил все11 файлов с V1 до итогового обновления Markdown, Go не менялся. Пользователь разрешил коммит после PASS. [Scope](../planning/multi-project.md#jwt-и-native-двух-проектов--mp5-token-http), evidence/история — history.

## Дальше

Следующий блок — two-project OIDC callbacks/state/PKCE/nonce. Directory/identity pending и полная email HTTP/browser matrix, public project lifecycle/fault/fleet остаются gates полной MP5. Затем A6.3m.6 email/Telegram second factors, backend templates, security/refactor и MP7/MP8 ресурсы/maxRPS. UI только после предупреждения и отдельного согласования.

## Проверки

Чат «Проверки Auth — Luna» `01a16eab-c777-78a0-a815-47b45ff0860d`, host local, cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:29`. Main не запускает tests/lint/SQL и не ждёт полный прогон. Текущий блок принят: task check с Go1.27.3/pinned lint2.14.0 и ^TestTwoProjectTokenIsolationSQL$ -race -count=1. Не повторять без изменения затронутых гарантий. Shared helpers/прежние roots не менялись — не повторять формально. Старый installed lint не подходит Go1.27.3.

Own PG18.6/Redis8.2/TLS/SCRAM/readonly /src; explicit disposable auth_prepare_catalog_test/auth_storage_test ENV, RedisDB15 exact-key cleanup. Legacy TestPrepareCommandSQL не нужен. Реальные ENV/DB/staging не трогать. Native email/MFA и rotation/fleet этим новым root не перепроверяются.

Прежний MP5-sessions-email принят Luna V1/V2 и закоммичен 5df1020; snapshot /private/tmp/auth-two-project-sessions-email-v2.w8ce8ztd, evidence v1/v2 siblings. Это не результат текущего изменения.

MP5-token-http V1 snapshot `/private/tmp/auth-two-project-token-http-v1.tri3xhsi`; manifest/metadata рядом, base `5df1020a669e71bdc962a011e9a87826ccddfa03`. Принят Luna V1; evidence /private/tmp/auth-two-project-token-http-v1-* и manifest/metadata рядом.
