# Повторные циклы нагрузки и отдыха

Дополнение к [HTTP baseline](load-baseline.md), не максимальный RPS или production soak. Только существующий изолированный `auth-sandbox` и synthetic accounts. Рабочие БД/env/secrets не используются.

## Запуск и критерии

```sh
task sandbox:load:rest
```

Не запускать одновременно с другими acceptance runners, сборкой или тяжёлыми host jobs: общие ресурсы влияют на latency. Нужны те же JWT/admin/TOTP fixtures, что и `sandbox:load`. Opt-in `AUTH_SANDBOX_LOAD_REST=1`, timeout14m. По умолчанию обычные Go tests пропускают live runner.

- Исходный production binary/image не меняется. Только API временно пересоздаётся с `GODEBUG=gctrace=1,schedtrace=15000,scheddetail=1`; cleanup возвращает прежний deployment без GODEBUG. Нет нового diagnostic HTTP endpoint, heap dump, зависимостей или GC tuning. Диагностика имеет overhead и относится к этому профилю, не к исходному performance baseline.
- Прогрев10RPS15s и один burst8 password login; отдых75s формирует warmed baseline. Затем два одинаковых цикла: burst8 login → mixed50RPS90s → отдых75s. По уточнению пользователя третий цикл убран. Mix и safety bounds/16 workers/3s request deadline те же, что в baseline. Исходные quotas/hash slots/session/JWT TTL/retention не меняются. Readiness/user/admin/JWKS проверяются отдельно от mix.
- HTTP критерии остаются прежними: ≥98% заданного RPS, без dropped/unexpected responses, per-route p95≤250ms/p99≤500ms. Login burst отдельно:503 допустим как bounded hash shedding, не successful throughput. После нарушения проверка останавливается, исходный deployment восстанавливается; не повышать пороги ради PASS.
- Снимки на warmed-rest/load-end/rest-end: RSS из `docker top -eo pid,rss` одного API процесса в KiB; Docker требует PID в ps output. Container ID/running/restart count проверяются до и после. Не сравнивать снимки разных запусков и не считать Docker memory точным RSS.
- Scheduler trace каждые15s: считать G descriptors, исключая idle/dead/deadextra и маскируя scan bit по исходникам Go1.27.2. Учитывается только завершённый snapshot перед следующим заголовком; последний незавершённый отбрасывается. Это sampled active descriptors, включая runtime G, не точный `runtime.NumGoroutine` и не непрерывный peak.
- Предварительный локальный rest envelope: RSS≤256MiB и не более warmed RSS+64MiB; active descriptors≤warmed+16. Это диагностические пороги обнаружения заметного накопления за повторные циклы, не продуктовый SLO и не доказательство отсутствия медленной утечки.
- Gctrace: число циклов, округлённый live heap последнего события, maximum sampled live heap и сумма двух STW частей. Последний GC мог произойти до отдыха: не выдавать его за retained heap на конец отдыха. Нет forced GC/debug.FreeOSMemory. Raw application logs не печатаются; scheduler reader ограничен4MiB и имеет unit tests на incomplete/oversized input. Сам Docker log store регулируется отдельно; короткий прогон не заменяет log rotation policy.

## Аудит владельцев ресурсов

Прочитаны `app/auth/run.go`: cancel/join background и delivery workers, обратный once cleanup ресурсов; `auth/delivery/worker.go` и account retention: ticker.Stop/cancellation/bounded processing; HTTP shutdown: отдельный timeout после cancellation, force-close при ошибке. SMTP connection закрывается на всех выходах и прерывается через context cancellation; OIDC owner имеет cancel и закрытие idle HTTP connections; PostgreSQL pool закрывается после failed Ping. Это targeted code review, не runtime fault/restore proof и не полный аудит всех SQL rows/HTTP bodies.

## Результаты 18 октября 2026

Первый запуск остановился на warmup:150 HTTP200,0 drops, `/me` p99=515.455083ms при пороге500ms; остальные route gates пройдены. Полный load/rest сценарий не выполнен. Параллельно шёл `task check` на общем хосте; это возможный источник конкуренции, не установленная причина задержки. Production код и пороги не менялись. Исходный deployment восстановлен cleanup. Первый лог: `/private/tmp/auth-sandbox-load-rest.log`.

Второй запуск после общей компиляции прошёл HTTP warmup (max route p99=31.160042ms), но остановился через112.56s на новом RSS sampler: Docker отклоняет `top -eo rss` без PID. Исправлен только измеритель на `pid,rss`; пороги и production код не менялись, исходный deployment восстановлен. Этот запуск не является load/rest PASS. Лог: `/private/tmp/auth-sandbox-load-rest-repeat.log`.

Третий запуск с исправленным sampler выполнил два полных load/rest цикла, после чего пользователь запросил остановку без третьего. Пока команда остановки исполнялась, третий цикл начал login burst/начальную нагрузку: он прерван, его данные не входят в результаты ниже. Runner завершён сигналом; итоговый `go test` PASS не заявляется. Исходный API восстановлен вручную теми же Compose files без diagnostic override. В исходнике число циклов сокращено до двух, повторный live прогон не выполнялся по просьбе пользователя.

| Снимок / окно | Successful HTTP / RPS | Max route p95 / p99 | RSS MiB | Active G descriptors |
| --- | --- | --- | --- | --- |
| Warmed rest | — | — | 219.32 | 29 |
| Цикл1,90s нагрузка | 4496 /49.95 | 13.91 /27.54ms | 313.71 на load-end | 29 |
| Цикл1,75s отдых | — | — | 230.88 | 23 |
| Цикл2,90s нагрузка | 4497 /49.96 | 13.64 /31.30ms | 304.66 на load-end | 32 |
| Цикл2,75s отдых | — | — | 229.29 | 24 |

Два окна:8993 HTTP200/0 drops/0 unexpected errors. Warmup150 HTTP200 отдельно; JWT exchanges/login/readiness не включены в mixed RPS. Во всех завершённых login bursts2×200/6×503: bounded hash slots, не измерение sustained login RPS. Максимум32 active descriptors среди завершённых scheduler snapshots до конца второго отдыха, включая runtime G; это не непрерывный peak или точный runtime.NumGoroutine. Оба rest envelope пройдены, устойчивого роста между двумя rest снимками не обнаружено; короткий профиль не доказывает отсутствия медленной утечки. GC summary в конце runner и его финальные user/admin/JWKS assertions не выполнены из-за остановки, их не отмечать PASS.

Docker VM4CPU/3055443968bytes RAM, shared Linux/aarch64, тот же image `sha256:4eadba6429caf4c36fe3561dd0257fb9c4e10f8ab4af43c318448fd9aa0b19e0`. Одно read-only SQL наблюдение во время нагрузки:8 runtime connections/0 lock waiters/0 deadlocks/0 temp bytes, не continuous peak. Лог третьего запуска: `/private/tmp/auth-sandbox-load-rest-final.log`. После ручного восстановления подтверждены исходный image/7 mounts/HTTPS readiness200; временный override удалён. Raw credentials/bodies/heap dumps не сохранялись в отчёте.

## Открытые проверки

Gofmt, scheduler parser unit tests/targeted unit `-race` и итоговый `task check` PASS/lint0; `git diff --check` PASS. Live server/runner не instrumented -race, scanner/full SQL/fault не повторялись. Восстановление: GODEBUG отсутствует,4 контейнера работают, зависимости healthy; удалён только созданный temporary override и его пустой каталог. Проверки не требуют нового live запуска после сокращения default до двух циклов.

Многочасовой soak, несколько API instances, mixed SMTP/provider/SQL/Redis timeout/failure и cancellation recovery, allocation rate/точный retained heap и GC CPU profiles, полная startup/shutdown/restore/fleet приёмка и maximum capacity остаются отдельными gates. Нет данных — NOT RUN. После multi-project повторить затронутые измерения по [MP8](../planning/multi-project.md).
