# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [MP5-oidc-http](../planning/multi-project.md#oidc-callbacks-двух-проектов--mp5-oidc-http). Git/staging проверять по факту.

## Завершён MP5-oidc-http — Luna V4 PASS

TestTwoProjectOIDCIsolationSQL: actual Google/Telegram A/B start/callback через controlled TLS token/JWKS provider с production client/verifier. RS256/issuer/audience/nonce/S256/client credentials/redirect, чужие state/cookies/provider/code, duplicate binding/replay, независимые UUID между проектами/issuers/no email merge, provider revisions и no-secret fallback. Warm missing credentials публично дают503 без session/exchange, после restore старый flow400 и fresh login успешен. Это не public admin rotation sign-off.

V1 task check PASS; V4 targeted lint и actual OIDC root race/count1 PASS. Cleanup и manifest10 подтверждены Luna; main сверил все10 файлов/base HEAD перед итоговым обновлением Markdown, Go не менялся. Fixture V1–V3 ошибки registration flag/empty secret consistency/public error expectation исправлены без production/API/mappers изменений; FAIL/evidence в history. Snapshot `/private/tmp/auth-two-project-oidc-http-v4.6oztj2f4`, manifest/metadata рядом, base `59f751af2714e3e631c999393e12c29fee90e2d7`; evidence `/private/tmp/auth-two-project-oidc-http-v1-*` … `v4-*`. Shared helpers/schema/ENV сервиса/deps прежние. Пользователь разрешил коммит после PASS, researcher закрыт, UI не начинался.

## Следующий блок

Сверить оставшиеся directory/identity linking pending, email HTTP/browser и public project lifecycle/fault gates полной MP5; этот login root сам не закрывает MP5. Затем A6.3m.6 email/Telegram second factors, backend templates, security/refactor и MP7/MP8 ресурсы/maxRPS. Внешние provider/browser/ingress/fleet отдельно. UI только после предупреждения и отдельного согласования.

## Проверки

Только «Проверки Auth — Luna» `01a16eab-c777-78a0-a815-47b45ff0860d`, host local, cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:33`. Main tests/lint/SQL не запускает и не ждёт полный прогон. Принятые проверки без изменения затронутых гарантий не повторять. Pinned Go1.27.3/lint2.14.0; старый installed lint не подходит.

Own PG18.6/Redis8.2/TLS/SCRAM/readonly /src; disposable auth_prepare_catalog_test/auth_storage_test ENV/RedisDB15 exact-key cleanup. Для OIDC root отдельный process и runner-container aliases oauth2.googleapis.com,www.googleapis.com,oauth.telegram.org →127.0.0.1, свободный loopback443 и право bind. Root ставит fixture CA через process-only SSL_CERT_FILE/SSL_CERT_DIR до bootstrap/system roots cache; host/DNS/реальные ENV/DB/endpoint settings не менять, TLS/verifier guards не ослаблять. Подробности стенда в scope. Legacy TestPrepareCommandSQL не нужен.
