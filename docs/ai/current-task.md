# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [MP5-directory-identity-http](../planning/multi-project.md#пользователи-и-привязки-двух-проектов--mp5-directory-identity-http). Git/staging проверять по факту.

## Завершён MP5-directory-identity-http — Luna V1/V2 PASS

TestTwoProjectDirectoryIsolationSQL: actual A/B list/card/filters/cursor, same UUID/email с разными metadata, own exclusive IDs, foreign cookies/card denial, ordinary permission guard/users.read revoke A при работающем B; read не требует fresh proof. TestTwoProjectIdentityManagementIsolationSQL: оба OIDC link callback/unlink с production verifier/controlled TLS provider, pending/session scopes, same-user other-session/missing/foreign proof, freshness recheck при SQL commit, no new account/session/version на link, replay, A-only unlink/revoke при сохранении B.

V1 Go tests и оба actual SQL roots race/count1 PASS; V2 targeted lint PASS после удаления unused helper return (поведение прежнее, SQL повтор не требовался). Cleanup и manifest11 подтверждены Luna; main сверил все11 файлов/base HEAD с V2 перед итоговым обновлением Markdown, Go не менялся. Snapshot `/private/tmp/auth-two-project-directory-identity-v2.4fxp2iji`, manifest/metadata рядом, base `6a0cc6f634dc00017c554a4d0221d87e4a6ce409`; evidence `/private/tmp/auth-two-project-directory-identity-v1-*` и `v2-*`, подробности в history. Production/shared helpers/schema/ENV/deps прежние. Пользователь разрешил коммит после PASS, researcher закрыт, UI не начинался.

## Следующий блок

Двухпроектная email HTTP matrix: компонентные verify/reset/invite/temporary/change/report/recovery уже приняты, теперь проверить HTTP/pending/source-session/origin guards на существующей fixture. Затем public project lifecycle/fault gates; весь MP5 пока открыт. Далее A6.3m.6 email/Telegram second factors, backend templates, security/refactor и MP7/MP8 ресурсы/maxRPS. Реальные provider/browser/ingress/fleet отдельно. UI только после предупреждения и отдельного согласования.

## Проверки

Только «Проверки Auth — Luna» `01a16eab-c777-78a0-a815-47b45ff0860d`, host local, cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:35`. Main tests/lint/SQL не запускает и не ждёт полный прогон. Принятые проверки без изменения их гарантий не повторять. Pinned Go1.27.3/lint2.14.0. Actual roots отдельными процессами, legacy TestPrepareCommandSQL не нужен.

Own PG18.6/Redis8.2/TLS/SCRAM/readonly /src и disposable auth_prepare_catalog_test/auth_storage_test ENV/Redis15 exact-key cleanup. Identity/OIDC root использует runner aliases oauth2.googleapis.com,www.googleapis.com,oauth.telegram.org→127.0.0.1/free443 и process-only fixture CA до system root cache; Directory не требует aliases. Host/DNS/реальные ENV/DB/settings не менять, TLS/verifier guards не ослаблять.
