# Lifecycle проектной доставки

MP4.1f,25 октября2026. Решение перед реализацией.

- Подключить existing ProjectDelivery к платформенному server lifecycle, opt-in/default-off. Disabled не создаёт reader/registry/Redis/worker ради доставки.
- Требовать включённые platform и project runtime, отдельный trusted SMTP target allowlist и положительные ограниченные interval/page/parallelism настройки. Не подставлять SMTP/password/key платформы.
- Один runner на экземпляр, общий bounded parallelism для всех страниц/проектов. Он использует имеющиеся registry/private reader/shared Redis, без новых pools и Redis clients. Часть MaxAcquiring оставить HTTP/другим работам; fleet ceiling вычислять по объявленному числу instances с surge. Это статический потолок, не distributed allocator и не замер RPS.
- Запуск после успешной сборки dependencies; ошибки конфигурации — до начала серверного трафика. Отмена/ошибка сервера останавливает runner, ждёт current bounded SMTP/SQL completion, затем закрываются registry/private/shared dependencies. Failed-start cleanup не оставляет фоновых workers.
- Сохранить existing source/project scope/claim/lease/retry и safe reporting без payload/tokens/secrets. Никакого public-ready/UI cutover. Остальные email queues/retention/fleet fairness остаются отдельными этапами.
- Проверки: config disabled/enabled/dependency/budget/allowlist boundaries, lifecycle startup/error/cancel/drain, no extra pools/HTTP-independent scheduler; full task check/affected race и релевантная actual SQL/Redis assembly. Выполняет отдельная Luna.

## Настройки

| ENV | Default | Назначение |
| --- | --- | --- |
| PLATFORM_PROJECT_DELIVERY_ENABLED | false | Включить runner только в platform profile с project runtime |
| PLATFORM_PROJECT_DELIVERY_PARALLELISM | 2 | Максимум параллельно обслуживаемых проектов на экземпляр |
| PLATFORM_PROJECT_DELIVERY_PAGE_SIZE | 16 | Размер страницы между1 и StateBatchSize, не меньше parallelism |
| PLATFORM_PROJECT_DELIVERY_INTERVAL | 5s | Пауза между страницами/повторами выборки, допустимо1s–1m |
| PLATFORM_PROJECT_DELIVERY_FLEET_CONCURRENCY | 8 | Объявленный потолок projects-in-flight для всех API instances с surge |
| PLATFORM_PROJECT_DELIVERY_SMTP_ALLOWED_TARGETS | пусто | Явный allowlist host:port через запятую,1–16 адресов |

Для enabled startup требуется `parallelism <= MaxAcquiring/2`, `parallelism <= MaxRuntimes` и `APIInstances × parallelism <= FleetConcurrency`. Умножение проверяется через безопасное деление. Резерв admission slots не гарантирует выделенные SQL connections или fairness; HTTP и workers используют те же bounded pools. Pool budgets по экземплярам уже учитываются platform SQL validation, второй раз worker connections не прибавляются. FleetConcurrency — согласованная конфигурация deployment, не глобальный Redis semaphore; запуск лишних неучтённых replicas нарушает объявленный бюджет.

## Сборка и остановка

`config.PlatformConfig.Delivery` проверяется до открытия project runtime при сборке operator realm. `assembleProjectDelivery` использует уже созданные dependencies и добавляет конкретный non-nil worker в existing realm.workers. Disabled возвращает nil до обращения к dependencies. Объект создаётся на assembly, но запуск происходит только в realm.run рядом с другими delivery workers, после успешной сборки handlers.

`ProjectDelivery.RunDelivery` адаптирует существующий Run к общему контракту. При server return/error/cancellation existing runWithDelivery отменяет контекст и join workers, затем App.Close освобождает LIFO resources. Ошибки работы передаются в существующий safe email reporter без error text/payload. Ошибка config/assembly не запускает worker; existing cleanup закрывает ранее открытые собственные resources. Worker не делает собственный global setup или project preparation.

## Проверки и границы

Добавлены config boundary/disabled/dependency/allowlist/fleet tests и lifecycle drill в actual TestProjectRuntimeAssemblySQL: empty catalog polls без HTTP, normal serve return/error/context cancel, running=false до resources close и restart того же runner после join. Redis в этом empty-catalog fixture ленивый и не вызывается; реальные project outbox/Redis/SMTP-rejection cases проверены MP4.1e command suite. Внешняя SMTP-доставка этим lifecycle drill не проверяется.

Formatter/diff выполняет main, task check/affected race/actual assembly SQL — отдельная Luna на snapshot. Luna V2: task check exit0/lint0 и config race exit0; V1 app/auth race и actual TestProjectRuntimeAssemblySQL exit0 без SKIP. Manifest9 совпал до/после и с main; owned PostgreSQL/schema/reader role/session cleanup подтверждён. После V1 изменена только группировка config validation, успешный actual SQL не повторялся. Локальный verification завершён; evidence — history. HTTP/readiness/UI, остальные outbox/retention, fleet outage/fairness и MP8 capacity/GC остаются открытыми.

MP4.1h [расширяет account очереди](project-account-runtime.md) без новых workers/ENV/pools: verification/change/invitation/binding получают последовательный приоритет по полным catalog sweeps. Reset сохраняет отдельную попытку. MFA/OTP/retention/fleet acceptance не закрываются этой ротацией. Проверки нового diff отдельно от MP4.1f.
