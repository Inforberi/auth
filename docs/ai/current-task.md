# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [MP5-email-http](../planning/multi-project.md#почтовые-http-сценарии-двух-проектов--mp5-email-http). Git/staging проверять по факту.

## Завершён MP5-email-http — Luna V2/V4 PASS

TestTwoProjectEmailHTTPIsolationSQL: actual A/B HTTPS verification/reset, invitations/temporary issuance и completion, change/report/recover, binding approval/target-session. Чужие credentials/tokens/Origin, replay и отзыв только своих sessions; completion не создаёт login. Другая живая session target допустима; approval привязан к session администратора. Реальный delivery worker/SMTP probes без STARTTLS подтверждают безопасный отказ, не внешнюю доставку. OIDC identity/session для binding — SQL-предпосылка.

V2 task check PASS; V4 targeted pinned lint и actual SQL race/count1 PASS. Штатный cleanup оставил Redis15 пустым и PostgreSQL resources clean, manifest12 подтверждён Luna. Main сверил все12 файлов/base HEAD перед итоговым обновлением Markdown, Go не менялся. Snapshot /private/tmp/auth-two-project-email-http-v4.dcl1it33, manifest/metadata siblings, base17e63f67913bee68f40c8651b6144af99f7aa76f. Evidence /private/tmp/auth-two-project-email-http-v4-* и task check V2; fixture FAIL/исправления — history. Production/shared helpers/schema/ENV/deps прежние. Пользователь разрешил коммит после PASS.

## Следующий блок

Public project lifecycle/fault gates; полный MP5 открыт. Затем A6.3m.6 email/Telegram second factors, backend templates, security/refactor, MP7/MP8 ресурсы/maxRPS. Reissue HTTP/browser/реальные provider/SMTP/ingress/fleet отдельно. UI только после предупреждения и отдельного согласования.

## Проверки

Только «Проверки Auth — Luna» 01a16eab-c777-78a0-a815-47b45ff0860d, host local, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:39. Main tests/lint/SQL не запускает и не ждёт полный прогон. Принятые roots при прежних helpers не повторять. Go1.27.3/lint2.14.0; actual roots отдельными процессами, legacy TestPrepareCommandSQL не нужен.

Own PG18.6/Redis8.2/TLS/SCRAM/readonly /src, disposable auth_prepare_catalog_test/auth_storage_test ENV, Redis15 exact-key cleanup. Email HTTP root не требует OIDC aliases443. Host/DNS/реальные ENV/DB/settings не менять, TLS/verifier guards не ослаблять.
