# Нагрузка и защита ресурсов

SQL остаётся источником действительности доступа: status, auth_version, revoke и expiry проверяются на защищённых запросах. Redis используется для общих лимитов; при его недоступности вход закрыт, обхода через БД нет. Кеш действительности сессии не добавлен.

## Настройки

Все параметры задаются env при startup; изменения требуют restart. UI появится в конце плана. Это стартовые бюджеты, а не обещание заданного числа пользователей.

| Параметр | Default | Область |
| --- | --- | --- |
| `HTTP_MAX_IN_FLIGHT` | 128 | Одновременно выполняемые обработчики одного API; лишние сразу получают 503 и Retry-After 1 |
| `HTTP_REQUEST_TIMEOUT` | 10s | Контекст HTTP-запроса; credential/session lookup и регистрационная транзакция дополнительно ограничены 5s |
| `PASSWORD_HASH_CONCURRENCY` | 2 | Общий бюджет hash/compare для login/register/change/reset/email-change/recovery одного процесса |
| `LOGIN_IP_LIMIT` | 30 | Попытки входа с IP в минуту |
| `LOGIN_EMAIL_LIMIT` | 10 | Попытки входа для email в минуту |
| `LOGIN_GLOBAL_LIMIT` | 1000 | Попытки входа в минуту для всех API с общими Redis и ключом |
| `REGISTER_IP_LIMIT` | 5 | Регистрации с IP в минуту |
| `REGISTER_GLOBAL_LIMIT` | 100 | Общие регистрации в минуту |
| `PASSWORD_RESET_GLOBAL_LIMIT` | 100 | Общий reset и защитный recovery в минуту |
| `RETENTION_BATCH_SIZE` | 100 | Максимум кандидатов каждой операции cleanup; 1–1000 |
| `RETENTION_INTERVAL` | 1m | Один проход cleanup, без бесконечного draining; 1s–1h |
| `HTTP_TRUSTED_PROXY_CIDRS` | пусто | Только сети собственного reverse proxy, через запятую |

Хеширование не ставится в безлимитную очередь: занятые слоты возвращают 503. Криптографические параметры и формат старых hashes не ослаблены. Новый hash использует 64 MiB; поддерживаемый старый hash может потребовать 256 MiB. Бюджет RAM считать по худшему поддерживаемому hash, количеству слотов, запасу Go heap и прочим ресурсам, а не только по обычному паролю. Argon2 нельзя прервать посередине: отменённый запрос удерживает слот до завершения вычисления, результат не используется. Контекст запроса не является жёстким таймером остановки CPU.

Redis-лимиты fixed-window, ключи HMAC без открытого email/IP. Это защита ресурсов и перебора, не гарантия постоянного RPS на границе минут. Под перегрузкой возвращаются 429/503, а не неограниченные ожидания. Повторять с Retry-After и jitter, не немедленным циклом. Лимит email может временно задержать легитимный вход при атаке; CAPTCHA/дополнительные сигналы требуют отдельного сценария.

## SQL и фоновые задачи

Обычная проверка сессии — один indexed lookup по token hash и user PK. Refresh не выполняется при достигнутом absolute expiry. Обновление сравнивает прочитанный expires_at, продлевает только вперёд и повторно проверяет действительность: конкурентные запросы не сокращают срок и не записывают одну прочитанную версию многократно. У already-refreshed запроса нет повторного Set-Cookie.

Claim письма больше не запускает DELETE по всей таблице. Очередь проверяет expiry/status/version и eligibility текущего challenge. Cleanup отделён в retention worker: ограниченные партии, SKIP LOCKED и expiry/exhausted indexes. Протухшие токены недействительны сразу, физическая очистка может отставать. User status/password/deletion mutations удаляют свои challenges атомарно; оставшиеся stale данные не отправляются и очищаются не позже expiry плюс backlog. Кандидаты по времени выбираются относительно statement_timestamp, фактическое потребление токенов и lease используют текущие часы БД.

Retention contacts/sessions/audit остаётся одной атомарной партией. Delivery cleanup выполняется следующими отдельными bounded statements: их частичный успех сохраняется при ошибке, повтор идемпотентен. Email-change cleanup включён в активном email-change профиле. Индекс intent expiry совпадает с GREATEST(protect_until,recovery_expires_at). Полное опустошение очередей на startup не выполняется.

Default capacity одной таблицы cleanup — до 144000 кандидатов в сутки на API; несколько правил/таблиц обрабатываются независимо. Увеличение batch/частоты повышает давление на БД: сначала измерить backlog и SQL latency. Лимит contacts может задерживать release пользователя с несколькими контактами. Лимит кандидатов не равен точному количеству каскадно удалённых строк.

## Сеть и эксплуатация

Без trusted CIDR X-Forwarded-For игнорируется. Для доверенного peer цепочка разбирается справа налево до первого недоверенного адреса; некорректный заголовок не становится ключом лимита. Proxy обязан корректно дописывать или перезаписывать заголовок. Не доверять всем сетям и не открывать прямой API доступ в обход proxy. Default пустой: за proxy все пользователи разделят socket-IP лимит, пока не настроены конкретные CIDR.

Readiness объединяет параллельные probes и использует результат не более секунды, без кеширования прав пользователей. Liveness не занимает admission slot. Заголовки ограничены 16 KiB, JSON — 1 MiB; неправильный формат session cookie отсекается до SQL. Admission ограничивает обработчики, но не все TCP/idle connections: на TLS ingress нужны connection/rate/body/header limits и защита от slow clients.

В production повторяющиеся application/access logs используют sampling: первые 100 сообщений одного level/message за секунду, затем каждое сотое. Dev logs не сэмплируются. Это снижает log-storm при overload; SQL security audit не сэмплируется и не зависит от logger. Счётчики/частоту ошибок измерять метриками, не количеством sampled logs.

Для N API общий верхний предел их SQL connections равен N × MAX_CONNS: нынешние background workers используют тот же pool и уже входят в этот бюджет. Дополнительно резервировать connections для migrations/operator и будущих отдельных worker-процессов со своими pools. Не увеличивать pool автоматически вслед за числом пользователей: измерять ожидания acquire, CPU/IO/locks, SQL latency, Redis latency, HTTP 429/503, Argon2 CPU/RAM, delivery backlog/age и lag cleanup. Полноценные metrics/alerts остаются этапом 14.1; текущие logs не заменяют эти метрики. Инстансы одного проекта используют одну политику лимитов и один scoped operational key. Между независимыми проектами нужны собственные БД/ключи/Redis isolation.

## Локальные результаты и оставшаяся приёмка

На PostgreSQL 18.6 проверены конкурентный refresh (32 запроса, одна запись), отзыв/блокировка/reset/delete и ограниченная очистка. На 100000 синтетических live rows и 10000 молодых tombstones пустые candidate ranges sessions/audit/reservations/challenges/outbox/intents использовали Index Cond и 2–3 shared buffers. Это проверка candidate SQL, не полного mutation throughput.

SQL-only session-read прогон: 2000 обращений, 32 читателя, pool 10; локальный результат около 10159 reads/s, p95 5.4ms, p99 20.4ms. Это короткий warm/local Docker PostgreSQL прогон, без HTTP/TLS/Redis/Argon2/SMTP; число нельзя выдавать за гарантированный API RPS. Общие admission/hash budgets проверены bursts по 1000 лишних операций и race detector. На Redis 8.2 из 200 попыток двух клиентов shared quota допускала ровно 10; TTL и отказ при недоступности проверены.

Повторение: обычный task check, отдельный race по затронутым пакетам; SQL correctness через AUTH_SCHEMA_TEST_DATABASE_URL и TestPostgresSchema. Query/load fixture — отдельная свежая localhost auth_schema_test БД с ролью auth_schema_test, AUTH_QUERY_PLAN_DATABASE_URL и TestPostgresQueryPlans; она создаёт синтетические данные, не предназначена для рабочей БД. Не запускать оба SQL набора с одной занятой fixture. Redis fixture — AUTH_LOGIN_TEST_REDIS_ADDR и TestDistributedLoginLimits, только disposable loopback Redis.

До release согласовать реальные active sessions/RPS/login peaks/P95/P99/CPU/RAM, провести длительный mixed HTTP+crypto+SMTP тест нескольких API, timeout/failover/recovery и backlog drain. Без этих измерений этап 6.8 не закрыт. Шаблон защищён от конкретных найденных unbounded операций, но «любое количество без проблем» не обещается.
