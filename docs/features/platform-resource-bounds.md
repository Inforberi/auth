# Бюджеты ресурсов платформы

## Границы

Платформенный deployment проверяет суммарный потолок SQL и ограничивает текущие HTTP-операции каталога: list/read/create/suspend/resume/retry и opt-in role create/read/reconcile. SQL-проверки session/permissions/fresh MFA и транзакционные гарантии сохраняются. Admission управляет ресурсами, не выдаёт полномочия.

Это часть MP4.3/MP4.5. Project Auth assembly, ограниченный scheduler фоновых работ, проверка нового role HTTP bridge и замеры MP8 ещё отдельно. Прямые вызовы repositories/CLI не проходят HTTP admission; будущие административные маршруты должны явно подключать его. Общий HTTP admission и deadline продолжают действовать, включая этап проверки сессии до проектного лимита.

## SQL: проверка конфигурации перед запуском

| ENV | По умолчанию | Значение |
| --- | --- | --- |
| `PLATFORM_API_INSTANCES` | 1 | Максимум одновременно работающих экземпляров, включая rolling-update surge |
| `PLATFORM_SQL_CONNECTION_BUDGET` | 80 | Доступный всему deployment потолок, после резервов самого PostgreSQL и других приложений |
| `PLATFORM_SQL_EXTERNAL_RESERVE` | 4 | Резерв отдельным migrators/workers/provisioners и другим внешним клиентам |

Для включённого project runtime проверяется:

```text
instances × (MAX_CONNS + 2 + MAX_RUNTIMES × MAX_CONNECTIONS) + external_reserve <= SQL_CONNECTION_BUDGET
```

`2` — private catalog reader, используемый также периодической сверкой. `MAX_RUNTIMES`/`MAX_CONNECTIONS` — переменные с префиксом `PLATFORM_PROJECT_`. Если runtime выключен, private/project pools в сумму не входят. Workers, уже использующие основной pool, не добавляются повторно. [Project delivery lifecycle](project-delivery-lifecycle.md) добавляет opt-in scheduler на этих же pools: worker connections не прибавляются повторно. Его parallelism резервирует acquiring capacity и проверяется отдельно по числу instances; это не distributed fleet allocator.

Пример: 10 основных + 2 reader + 8 × 4 проектных = 44 на API. Два API и резерв4 требуют минимум92; default80 такой deployment отклонит. Расчёт проверяет верхнюю границу без переполнения, а не ожидаемое среднее число открытых соединений. Project MinConns остаётся0, существующие pool/registry limits действуют дополнительно.

Это статическая проверка объявленной топологии, не распределённый allocator и не автоматическое обнаружение replicas. Все экземпляры должны иметь согласованные настройки. Перед масштабированием изменить число экземпляров и бюджет. Если БД распределены по разным PostgreSQL-серверам, общий консервативный потолок не заменяет проверку нагрузки и лимитов каждого сервера.

## Административные операции

| ENV | По умолчанию | Область |
| --- | --- | --- |
| `PLATFORM_OPERATIONS_MAX_IN_FLIGHT` | 8 | Все операции в одном API |
| `PLATFORM_OPERATIONS_ACTOR_MAX_IN_FLIGHT` | 2 | Один оператор в одном API |
| `PLATFORM_OPERATIONS_PROJECT_MAX_IN_FLIGHT` | 2 | Один проект в одном API |
| `PLATFORM_OPERATIONS_GLOBAL_PER_MINUTE` | 600 | Все API одного platform realm |
| `PLATFORM_OPERATIONS_ACTOR_PER_MINUTE` | 120 | Один оператор во всех API realm |
| `PLATFORM_OPERATIONS_PROJECT_PER_MINUTE` | 120 | Один проект во всех API realm |

Одновременно учитываются global/actor/project. Local caps освобождаются после завершения HTTP-обработки; очереди, goroutine на ожидание и накопления записей завершённых операций нет. In-flight maps содержат только активные ключи. Отказ Redis/отмена запроса освобождает занятые local slots. Release идемпотентен.

Actor берётся из подтверждённой сессии, project — из сопоставленного URL, а не JSON/header. List/create используют общую полосу `catalog`, поскольку существующего project ID в их URL нет. URL project ID ограничен UUID. Ошибки формы UUID здесь ограничивают пространство resource keys; service/domain по-прежнему определяют предметные правила и права.

Redis выполняет один атомарный Lua-вызов: списать все три счётчика либо ни одного. Окно каждого счётчика —60 секунд от первого принятого обращения, не календарная минута и не sliding window. Отказы не создают новые ключи и не продлевают TTL. Scope prefix отделяет platform realms, ключи совместимы с одним hash slot; Redis Cluster этим прогоном не сертифицируется. Повреждённый счётчик/отсутствие TTL — закрытый отказ. Используется общий `infra/redislimit` с прежним алгоритмом MFA; её prefixes и порт `AllowAll` сохранены.

Аутентифицированная попытка учитывается до выполнения SQL guard: последующий403/400 или идемпотентный replay не возвращает минутный бюджет, поскольку работа уже затрачена. Это сдерживает и неуспешные административные запросы. Actor/project minute caps должны быть меньше global; настройки concurrency положительные и не выше общего process cap. Это ограничение влияния одного участника, не гарантия справедливого планирования при произвольном DDoS.

Локальные concurrency caps умножаются на число API; Redis minute budgets общие. Эти настройки не являются допустимым RPS обычного входа/сессий и не доказывают capacity сервиса.

## Ответы

| Ситуация | HTTP | Code | Retry-After |
| --- | --- | --- | --- |
| Исчерпан минутный бюджет | 429 | `rate_limited` | 60 |
| Заняты local slots / Redis недоступен / отмена | 503 | `temporarily_unavailable` | 1 |
| Неверный project UUID | 400 | `invalid_project` | — |

Ответы `no-store`, Redis failure не включает SQL fallback. `Retry-After: 60` — консервативный максимум окна, без дополнительного Redis round trip. Неизвестные внутренние ошибки не раскрываются клиенту. Swagger указывает429 для catalog и opt-in role операций.

## Проверки

Быстрые unit: SQL budget exact boundary/surge/overflow; global/actor/project/catalog concurrency; immediate reject; idempotent release; cancellation/outage cleanup; route parameter, session identity, headers и отказ до handler. Выполнены в основном чате.

Первый отчёт Luna: отдельные lint, Swagger reproducibility и scanner PASS. Общий check/router race FAIL на старой конфигурации Swagger fixture; она исправлена, целевой тест PASS. Остальные race packages PASS. Live Redis/MFA/operator SQL тогда NOT RUN из-за отсутствовавшего тега Redis. На V2 check/lint/router race, live Redis admission/MFA PASS (actual Redis8.2.6). Operator SQL/HTTPS FAIL только на cleanup8 ключей нового limiter; purpose добавлен в whitelist fixture cleanup. V3: отдельный повтор TestOperatorProfileSQLHTTPS PASS exit0, gofmt без diff, final DB15/schema/role cleanup PASS, manifest совпал до/после; собственный стенд удалён. Gate этого блока закрыт, полный MP4 остаётся открыт. Длительные fleet/load/GC проверки — MP8.
