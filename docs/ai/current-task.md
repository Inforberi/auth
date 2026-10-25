# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Текущий блок — MP5.1a selected-feature readiness

[Контракт](../features/project-feature-readiness.md). Добавлен BuildProjectProfile: explicit browser/native/JWT selection, реальные factory dependencies, coherent origin/key/full policy snapshot, per-feature safe readiness и копируемый route plan. Password без verification не требует SMTP; verification-only без hasher; reauth-only без primary OTP. Delivery должен реально работать с теми же shared resources. Provider credentials/callback и JWT issuer проверяются локально; browser session/MFA согласованы. Refresh требует SQL native policy; logout остаётся для настроенного native backend.

Main formatter/diff/source review завершён; read-only Helmholtz оставшихся конкретных ошибок не нашёл. Luna: task check/lint0, affected race, security и полный actual Linux ARM64 TestPrepareCommandSQL PASS (exit0, selected_feature_readiness без SKIP). Manifest15 совпал после проверок и с main. Собственный стенд очищен. Одна отмеченная scanner уязвимость в модуле не вызывается кодом. TestPostgresSchema отдельно не запускался; schema не менялась. Новых deps/schema/ENV/pools/workers нет. HTTP routing/phase-ready не подключены; UI не начинается.

Snapshot `/private/tmp/auth-project-readiness-v1.ixt_zact`, manifest `/private/tmp/auth-project-readiness-v1.ixt_zact-manifest.sha256`, metadata `/private/tmp/auth-project-readiness-v1.ixt_zact-snapshot.json`; base1889a4f. Source hashes сверять с main перед принятием результата; docs не подменяют фактический PASS.

## Следующий шаг

Проверки приняты, пользователь разрешил коммит; его фактический статус проверять Git. Следом — resident HTTP profiles/lifecycle, затем полная MP5 cookies/CORS/CSRF/callback/redirect matrix. Account/session/MFA management mounting, managed rotation, MFA recovery/retention/fleet fairness/MP6R/MP7/MP8 остаются отдельно. UI только после отдельного предупреждения и согласования.

## Процесс и ограничения

- Read-only researcher Helmholtz gpt-6-luna medium: 01a17292-5405-7341-bae9-f5884a755889, сохранять для reuse; Bohr закрыт.
- Исполняемые проверки — отдельный чат Luna 01a16eab-c777-78a0-a815-47b45ff0860d, host local, exact snapshot/cwd. Default6377/auth stale. Main не дублирует и не ждёт полный прогон. [Процесс](development-workflow.md).
- Actual SQL: собственный Linux ARM64 postgres18.6 container, source readonly /src, admin socket trust; TCP127 SCRAM/wrong-password deny, TLS+SAN127; Redis8.2 shared network DB15. SCRAM_HOST=127.0.0.1/TLS_CA/ROOT/src/Redis127 env обязательны. Не macHost/randomport/trustTCP.
- UsePool не сохраняет pool/services/async за callback. Current guard не обещает rollback committed in-flight действий; source/readiness point-in-time, не positive authority cache. Shared owners закрываются после drain.
- Новые deps только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Commit только по запросу. MP5.0 HEAD1889a4f проверен и закоммичен; его PASS не подтверждает текущий diff.
