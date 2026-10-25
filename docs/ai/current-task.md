# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1e project email/outbox

[Контракт](../features/project-email-runtime.md). Добавлены NewProjectEmail (verification Resend/Confirm и password Forgot/Reset), private reader PageRuntimes и opt-in ProjectDelivery.Run с bounded pages/parallelism. Existing scoped ciphers/Redis/claim/retry/transport; source credentialsInPool исключает nested acquisition. Origin/URLs trusted HTTPS, no ENV seed/fallback/newdeps/новой миграции. Partial ready/enabled index добавлен только в initial catalog schema. Данные рабочей БД не менялись.

Добавлены actual SQL+Redis issuance/worker TLS-rejection/retry/confirm/reset/replay/suspend/page tests и unit URL/concurrency/cancellation. Formatter/diff выполняет main; все executable checks переданы отдельной Luna: Luna V3 task check exit0/lint0 и app/auth race exit0; V2 config/cmd race и actual full command SQL PASS без SKIP. Manifest11 совпал до/после и с main; после V2 менялся только тип counter, SQL/другие успешные наборы обоснованно не повторялись. Snapshot `/private/tmp/auth-project-email-v3.5mpw8ae3`, manifest `/private/tmp/auth-project-email-v3-manifest.sha256`, metadata `/private/tmp/auth-project-email-v3-snapshot.json`. Локальный gate закрыт. Реальная внешняя TLS delivery/public routing/registration/other queues/lifecycle auto-start/fleet bounds этим блоком не подтверждены.


## Следующий шаг

После фиксации проверенного блока продолжить operational/lifecycle подключение bounded delivery, remaining email/registration/provider/token assembly и отдельные readiness/MP5 guards. Полный MP4.4/4.5 не закрывать внутренним opt-in runner. UI не начинать; дальше MP6R security/refactor, MP7/MP8 и отдельное согласование UI.

## Процесс и ограничения

- Единственный локальный исследователь Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889. Targeted read-only SMTP/worker/catalog/fixture карта; tests не запускает. Переиспользовать, не закрывать после ответа. Bohr закрыт по просьбе пользователя.
- Все executable checks — отдельный чат «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на explicit immutable snapshot/cwd; default6377/auth stale. Main не дублирует tests и не ждёт весь прогон. [Процесс](development-workflow.md).
- UsePool callback не сохраняет pool/service/async работу. Delivery держит bounded logical lease до completion; physical connection во время SMTP/hash не удерживается. Передавать pool-bound source наружу нельзя. Shared dependencies закрывает owner после drain.
- Current key guard не обещает мгновенную отмену SMTP/committed operations после финальной сверки. SQL authority/lease/retry scopes сохранять.
- PostgreSQL+обязательный Redis. Новые deps только с разрешения; реальные ENV/БД/secrets/staging сохранять. Коммит только по запросу. Предыдущий SMTP блок закоммичен f7914c4; его PASS не подтверждает текущие изменения.
