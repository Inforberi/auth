# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [MP5-email-otp-http](../planning/multi-project.md#email-otp-двух-проектов--mp5-email-otp-http). Git/staging проверять по факту.

## Завершён MP5-email-otp-http — Luna V1 PASS

Сверка MP5 актуализировала принятые directory/identity/email/lifecycle/fault блоки без повторных прогонов. TestTwoProjectEmailOTPHTTPIsolationSQL закрыл оставшийся локальный primary email OTP/reauth HTTP scope: реальные A/B HTTPS, чужие cookie/Origin/binding, wrong code/replay/GET, SQL primary/proof без password/MFA повышения, source-session-bound reauth/rotation одной session без влияния на B. External-only OIDC target/sessions — SQL-предпосылка fixture. Worker/SMTP probes подтверждают readiness/безопасный отказ, не внешнюю доставку.

Luna V1 task check и actual SQL race/count1 PASS, штатный Redis/PostgreSQL cleanup и manifest8 подтверждены. Main сверил все8 файлов/base HEAD со снимком перед итоговым обновлением Markdown; Go не менялся. Snapshot /private/tmp/auth-two-project-email-otp-http-v1.i35f4m9h, manifest/metadata siblings, base6ad30240c1de95ef46e8f2f0d0ad3d644bc5fdc8. Evidence /private/tmp/auth-two-project-email-otp-http-v1-*. Production/shared helpers/schema/ENV/deps прежние. Пользователь разрешил коммит после PASS; весь MP5 не закрыт автоматически.

## Следующий шаг

A6.3m.6: различение метода/assurance от consumeFactor до SQL session/native/JWT/critical authority, с сохранением TOTP/recovery и без неиспользуемого enum. Новые email/Telegram second factor flows не публиковать до readiness/security prerequisites. Затем backend templates, security/refactor, MP7/MP8 ресурсы/maxRPS. Реальные browser/provider/SMTP/ingress/network/fleet/full restart отдельно. UI только после предупреждения и отдельного согласования.

## Проверки

Только «Проверки Auth — Luna» 01a16eab-c777-78a0-a815-47b45ff0860d, host local, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:42. Main tests/lint/SQL не запускает и не ждёт полный прогон. Go1.27.3/lint2.14.0; actual root отдельным процессом, legacy TestPrepareCommandSQL не нужен, OIDC aliases443 не нужны.

Own PG18.6/Redis8.2/TLS/SCRAM/readonly /src, disposable auth_prepare_catalog_test/auth_storage_test ENV, Redis15 exact-key cleanup. Host/DNS/реальные ENV/DB/settings не менять. Принятые прежние roots не повторять при прежних helpers.
