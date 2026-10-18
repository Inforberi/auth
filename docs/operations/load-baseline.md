# Локальный HTTP baseline

Это первый ограниченный single-instance замер, не maximum capacity, production SLO или проверка тысяч уникальных пользователей. Стенд и synthetic accounts — [sandbox](local-sandbox.md). Полная приёмка остаётся [6.8b/c](../planning/implementation.md).

## Повторение и безопасность

```sh
task sandbox:load
```

Нужны работающий JWT sandbox, Иван с fixture permission и подготовленный admin/TOTP. Не запускать вместе с другими sandbox acceptance runners. Обычный `go test` пропускает live-профиль. На время прогона только API пересоздаётся с `GODEBUG=gctrace=1` через новый ignored temporary override; original profile/key/TTL возвращаются cleanup. Принудительное завершение может прервать cleanup: остановить runner, восстановить `task sandbox:jwt`, проверить original flags/mounts, затем удалить только его scratch directory. БД/Redis не сбрасывать.

Нет новых runtime routes, публичного pprof, зависимостей или shell-скриптов. GOGC/GOMEMLIMIT, hashing, Redis quotas, SQL authority и HTTP admission не ослабляются. Ключи/cookies/passwords/raw bodies не выводятся. Gctrace собирается до восстановления API; application logs отфильтровываются внутри runner и не печатаются. Debug trace имеет накладные расходы: результат относится именно к этому диагностическому профилю.

## Фиксированный профиль

| Фаза | Offered RPS | Длительность |
| --- | --- | --- |
| Прогрев, отдельно от основных результатов | 10 | 15s |
| Ступени | 10 / 25 / 50 | по30s |
| Короткий стабильный участок, не soak | 50 | 90s |
| Отдельный login burst | 8 одновременных попыток | до завершения запросов |
| Отдых | 0 | 45s, без forced GC |

Mix по циклу20 запросов:60% GET `/api/v1/auth/me`,25% GET `/api/v1/auth/access`,10% GET `/api/v1/admin/roles`,5% POST service `/api/v1/internal/auth/token/introspect`. Две исходные user/admin sessions, не отдельный пользователь на каждый запрос. Introspection использует dedicated Basic credentials без cookie/Origin; проверяется `active:true`, а не только HTTP200. Cookie exchange вне mix обновляет JWT каждые25s при original TTL1m; эти запросы не входят в reported mixed RPS. Это прямой Auth HTTP baseline, не нагрузка отдельного consumer/data-backend deployment.

Генератор: максимум16 workers, неблокирующая передача без очереди, bounded latency storage, HTTP timeout3s, keep-alive с максимум16 connections/host. При занятых workers учитывается dropped, а не скрытый backlog. Отдельно проверяется фактическая скорость, чтобы coalescing ticker/медленный генератор не выдавались за достигнутую нагрузку. Латентности — completed-request nearest-rank p50/p95/p99 по маршрутам, не queued end-to-end SLO; стадия ограничена максимум90s/50RPS.

Диагностические gates выбраны до прогона:0 неожиданных HTTP/transport/semantic failures,0 dropped, достигнуто≥98% offered rate, p95≤250ms/p99≤500ms по маршруту и readiness200 после фазы. Это консервативная проверка runner/staging, не согласованный продуктовый SLO и не поиск точки насыщения. Failed phase прекращает дальнейший рост нагрузки.

Login burst сохраняет LOGIN_IP30/min, EMAIL10/min и PASSWORD_HASH_CONCURRENCY2; вместе с setup это не больше9 попыток Ивана. HTTP503 допустим только здесь как bounded hash admission, не считается успешным login throughput. Credentials/Set-Cookie не сохраняются, но успешные обычные login sessions/audit штатно остаются в sandbox.

## Наблюдения и ограничения

Контейнерные CPU/memory/PIDs и aggregate PostgreSQL/Redis snapshots снимаются read-only снаружи runner. Docker memory — cache-adjusted container usage, не точный RSS/Go heap; PIDs включает kernel threads и не равен goroutines. SQL snapshots — cumulative statistics, не измерение pool acquire latency или per-query amplification. Не сбрасывать статистику/limiter keys ради красивого результата. Только auth-sandbox containers, без query texts/реальных env/user data.

GC summary сообщает число увиденных циклов, max/last live heap в округлённых MB и maximum сумму двух STW частей одного цикла; concurrent mark не объявляется паузой. Это не percentile всех пауз, allocation rate или доказательство отсутствия утечек. Во время45s rest новый GC не форсируется: последний live heap может относиться к более раннему циклу. Длительные одинаковые load/rest циклы, retained heap/allocs/goroutines, protected profiles, cancellation/fault/recovery и multi-instance всё ещё обязательны6.8b/c.

Worker/cleanup throughput нельзя вывести из нулевого backlog или роста cumulative deleted counters. Для него нужен отдельный разрешённый сценарий с измеряемой партией expired synthetic data и controlled drain; этот HTTP baseline не создаёт его SQL-подменами и не меняет сроки хранения.

## Результат 18 октября 2026

HEADcf06502 + test-only changes, Docker27.4.0/aarch64 VM4CPU/3055443968bytes (~2.85GiB), генератор Go1.27.2 darwin/arm64 на том же компьютере вне VM. Отдельных CPU/RAM reservations нет. Auth image `sha256:4eadba6429caf4c36fe3561dd0257fb9c4e10f8ab4af43c318448fd9aa0b19e0`; PostgreSQL18.6/Redis8.2/Mailpit1.27.10. Shared VM с остальной локальной работой, не dedicated load host.

`task sandbox:load` PASS267.67s. Ступени10/25/50 дали300/750/1500 completed requests, stable4499 за90.001s (49.99RPS). Всего7049 measured requests +150 warmup, все200, drops0. Exchange/setup/probes не включены в эти counts. Большая population/точка насыщения не проверялись.

Stable50RPS90s, nearest-rank latency:

| Маршрут | Count | p95 | p99 |
| --- | --- | --- | --- |
| me | 2700 | 9.40ms | 18.38ms |
| access | 1125 | 12.04ms | 34.65ms |
| roles | 450 | 11.57ms | 23.21ms |
| introspect | 224 | 12.29ms | 25.49ms |

На step50 worst per-route p99=40.42ms. Warmup introspection p99=163.70ms остаётся отдельным результатом, не скрывается и не смешивается со stable. Отдельный8-login burst:2×200/6×503, p99 всех ответов208.44ms. Это ожидаемый отказ при занятых hash slots, не измерение login RPS.

Resource snapshots (не непрерывные peaks; memory — Docker CLI cache-adjusted usage):

| Снимок | API CPU / memory | PostgreSQL CPU / memory | Redis CPU / memory |
| --- | --- | --- | --- |
| До запуска, original process | 0.14% / 11MiB | 4.36% / 54.14MiB | 0.80% / 9.867MiB |
| Setup после входов | 1.12% / 138.1MiB | 3.67% / 47.38MiB | 2.69% / 9.629MiB |
| Ramp, несинхронный снимок | 3.46% / 138.6MiB | 5.83% / 50.37MiB | 1.51% / 9.625MiB |
| Stable50 | 7.34% / 23.79MiB | 4.28% / 56.88MiB | 0.65% / 9.633MiB |

Sampled runtime connections4–5/limit10, lock waiters0. PostgreSQL cumulative commits +12241, rollbacks не выросли (97), deadlocks0/temp_bytes0, read blocks+20/hits+112000; inserted+19/updated+9/deleted+1 включают workers/proofs/audit/sampling. Redis commands+2324, rejected/evicted0. Эти delta не считаются per-route SQL/Redis round trips. Eligible sessions>30days (bounded LIMIT201) =0: cleanup throughput остаётся NOT RUN.

GC:38 cycles, max/last live heap130MB по trace, max combined STW4.704ms. Last trace относится к последнему произошедшему GC, не гарантированно к окончанию отдыха; hashing мог удерживать живые buffers. Не доказаны ни утечка, ни её отсутствие. Post-load/rest Docker memory sample попал на cleanup API recreate (0B/PIDs0), исключён как invalid; освобождение памяти после rest по нему не заявляется. Legacy256MiB hashes, allocation rate, retained heap/goroutines/profiles и длительные одинаковые load-rest циклы отдельно не измерены.

Gofmt/final `task check` (lint0)/targeted race unit tests профиля и percentiles PASS. Live performance test и server не instrumented `-race`. Style-only De Morgan predicate и unit tests уточнены во время прогона, semantics неизменны; полного повторного прогона ради этого не было. Scanner/full SQL/fault/restore suites не повторялись для test-only changes. Original API без GODEBUG, прежний kid/TTL/flags/7 readonly mounts/verified-CA readiness/JWKS восстановлены, volumes/пользователи/роли сохранены. Чувствительные fixtures не создавались в Git.

Подробности — [history](../planning/history.md#результат-pre-ui-load-baseline-local--18-октября-2026), сводка — [отчёт](acceptance-summary.md). Следующий отдельный блок: controlled expired-data backlog/drain и повторные длительные load-rest с защищёнными diagnostics. Не включать cache/GC tuning без новых измерений и не переносить эти цифры как гарантированную production capacity.

## Очистка backlog под HTTP нагрузкой

```sh
task sandbox:cleanup
```

Opt-in AUTH_SANDBOX_CLEANUP=1/timeout8m; не запускать с другими sandbox runners. Используется существующий API/SQL/Redis и исходный retention profile200/1m; saved session30/audit180days читаются через protected API и сравниваются после проверки, не меняются. Runtime/TTL/лимиты/worker code не тюнятся, API не пересоздаётся. Никаких ручных вызовов Purge, reset checkpoints/статистики или запуска отдельного worker.

Fixture — только новый blocked UUID без credentials, контактов, ролей и MFA. `cleanup_fixture.sql` встроен в Go test; через psql -X/ON_ERROR_STOP и quoted UUID variable транзакционно вставляются данные и снимается initial count до COMMIT. SQL fixture не является самостоятельной миграцией/скриптом для рабочей БД. Docker project guard допускает только auth-sandbox Postgres/API, операции ограничены statement/lock/command deadlines; не используются реальные ENV/данные.

| Fixture | Начальное число | Что ожидается от worker |
| --- | --- | --- |
| Sessions, завершены31day назад | 450 | Полный drain, не больше200 кандидатов/партия |
| Password audit,181day | 450 | Полный drain по собственному table budget200 |
| Недавно завершённые sessions,1day | 12 | Сохранить |
| Неистёкшие session ledgers | 12 | Сохранить |
| Старые session ledgers с future refresh-family reference | 12 +12 families | Сохранить обе стороны |
| Young audit,179days | 12 | Сохранить |

Held-reference fixture проверяет SQL guard, не изображает выданный native lifetime: её historical/future timestamps заданы явно для синтетического owner, который заблокирован и не может аутентифицироваться. Работоспособность настоящих user/admin sessions проверяется параллельным HTTPS API, не dummy ledgers.

Подаётся прежний mix50RPS три окна по90s; JWT обновляется каждые25s, используются прежние16 bounded workers/no queue и latency/error gates. Отдельный observer раз в5s считает только fixture UUID, не останавливая HTTP scheduler. Snapshot — один SQL statement/snapshot; для него доступны owner indexes. Counts могут только убывать, control группы не меняются, gap>30s делает наблюдение недостаточным для утверждения о минутных партиях. Логируются только изменения; state читается после cancel/join observer.

В конце должны быть0 expired sessions/old audit, остальные controls неизменны, ordinary user/admin `/me`200, saved retention version/policy прежние. Cleanup удаляет только fixture families/sessions/audit и её blocked UUID, затем подтверждает отсутствие owner. Это удаление искусственных проверочных данных, не пользовательский account-deletion workflow и не сброс БД; результаты/логи позволяют повторить fixture. При SIGKILL/timeout/ошибке cleanup остатки могут сохраниться: после остановки runner проверить напечатанный UUID/marker `sandbox-cleanup-*`, удалять только его, не чужие accounts/volumes/checkpoints.

Drain time — время видимости уменьшения/нулевого backlog с polling5s и задержкой SQL/Docker, включая ожидание первого worker tick, **не execution latency SQL DELETE и не максимально возможный rows/s**. Один API/по450 rows/одна audit table не доказывают длительную capacity всех очередей, contact release/refresh history drain/fleet/fault/GC. Поиск maximum RPS остаётся отдельным последним pre-ui gate.

### Результат cleanup18 октября2026

`task sandbox:cleanup` PASS293.13s. Remaining expired sessions/old audit:450/450 при commit →250/250 после35.114s →50/50 после95.119s →0/0 после155.119s.53 snapshots, observed max deletion200/таблица/партия, controls неизменны. Сроки/интервал/партия/checkpoints вручную не менялись; политика/version в конце прежние. Это три scheduled прохода, не benchmark самого DELETE.

| Окно HTTP | Completed / RPS | Max route p95 | Max route p99 |
| --- | --- | --- | --- |
| 1,90s | 4496 /49.95 | 11.36ms | 18.93ms |
| 2,90s | 4498 /49.98 | 11.98ms | 21.34ms |
| 3,90s | 4496 /49.95 | 11.20ms | 18.82ms |

Всего13490 HTTP200/0 drops/0 unexpected errors. Это maximum по отдельным route/window percentiles, не global percentile и не доказательство ускорения относительно прошлого run. Настоящие user/admin sessions работают после drain. Один sampled snapshot: API6.72% Docker CPU/140.5MiB, SQL8.20%/64.38MiB/connections5/10/lock waiters0/deadlocks0/temp0, Redis0.74%/9.641MiB. Не continuous peaks/RSS/goroutines/leak analysis.

После observer join fixture controls/owner удалены точечно; отдельная read-only проверка для UUID278c75ea-3fad-44a7-b938-b67bb0a10839 подтвердила owner/sessions/audit/families0. Existing containers/данные/настройки сохранены, HTTPS readiness200. Gofmt/task check lint0/targeted invariant-unit race/live PASS; это не server/live-observer race instrumentation. Подробности — [history](../planning/history.md#результат-pre-ui-cleanup-drain-local--18-октября-2026). Runtime/schema/dependencies не менялись; full SQL/scanner/other cleanup queues/fleet/длительный load-rest/GC/max RPS остаются отдельными проверками.
