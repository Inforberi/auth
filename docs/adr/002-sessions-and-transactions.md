# ADR 002: durable отзыв сессий и одноразовые операции

Статус: принято, 6 октября 2026. Реализация: 4, 5.1–5.4, 6.1–6.3, 8.4, 13.1.

Уточнено 9 октября 2026: сохраняем PostgreSQL + Redis, строгий отзыв доступа по умолчанию и оптимизацию по измеренной нагрузке. Предложение о 5 секундах задержки отзыва не принято; cache-only проверка сессий не включается в базовый профиль.

План 16 октября: [A6.4 JWT access](../planning/jwt-access.md) добавляет будущие transport profiles, не меняя это решение сейчас. Strict JWT использует текущую online authority; local-only JWT требует отдельного ADR о допустимом устаревшем доступе и не считается уже принятым ослаблением отзыва.

## Решение

Opaque session token генерируется криптографически; raw token хранится только в защищённой browser cookie. В серверном ledger — verifier/digest, user UUID, auth version, сроки, revoked state и authentication context. PostgreSQL — источник истины. На каждом защищённом запросе проверяется актуальный ledger и user status/version; Redis cache не заменяет эту проверку. Отзыв имеет силу для проверок, начавшихся после SQL commit; чувствительная запись повторно проверяет доступ внутри транзакции, блокируя конфликтующую смену версии/отзыв. Уже выполненный внешний эффект отозвать задним числом нельзя.

Single logout отзывает SQL session; logout-all/password reset/change/block повышают user auth version транзакционно вместе с изменением credentials/status. Redis cleanup best-effort после commit, а не security boundary. Refresh изменяет лишь существующую активную session условной атомарной операцией; не воскрешает revoked session. `now >= deadline` означает истечение; idle expiry/Redis TTL/cookie не выходят за absolute deadline. Token rotation не продлевает absolute срок.

Authentication context фиксирует серверно подтверждённые методы/время входа, fresh-auth и MFA; данные provider/client не становятся административными permissions. MFA/fresh-auth проверяются backend для чувствительных действий, отдельно от sliding TTL.

Уточнение AS6a, 16 октября 2026: фактическое новое назначение обычной или системной роли активному пользователю атомарно повышает auth_version цели вместе с access_version/assignment/audit. Старые sessions и version-bound in-flight login/challenges не наследуют новый grant; требуется новый обычный вход с действующим MFA. SQL user lock согласует это с session creation/refresh. Pending не может иметь действующую session и сохраняет auth_version для приглашения/активации; после активации действует обычная проверка версии. No-op grant не меняет версии, revoke убирает текущие permissions без обязательного отзыва session. Используется существующая version boundary, без UPDATE всех session rows, дополнительных hot-path запросов или Redis invalidation. Изменение permissions уже назначенной роли требует отдельного AS6b решения без массового fan-out UPDATE; этим уточнением оно не объявлено защищённым.

## Challenges, audit и доставка

Verify/reset/OTP/link challenges связаны с purpose/owner/intent, ограничены сроком и попытками; хранят verifier, не raw secret. Conditional consume и изменение аккаунта/credentials/auth version/security audit происходят одной SQL-транзакцией. Два concurrent consume дают ровно один успех. Недоставленное письмо не подтверждает identity. Повторная доставка использует outbox с ограниченными retry, сроком и dedup; resend policy явно инвалидирует прежний challenge.

Когда outbox должен хранить secret для отправки письма, payload защищается шифрованием с отдельным operational key, коротким retention и исключением из логов. Не обещаем exactly-once email; гарантируем безопасное повторение и одноразовое потребление. Доступ к audit ограничен, credentials/tokens/provider secrets в него не записываются. Критический audit/outbox write failure откатывает соответствующую domain transaction.

## Отказы и восстановление

Недоступна SQL/не подтверждён status/version — защищённый запрос отклоняется как dependency failure, а не принимается по cache. Redis недоступен — auth/challenge операции, зависящие от limiter или session инфраструктуры, временно недоступны; не разрешаем неограниченные попытки и не вводим скрытый fallback. Независимый liveness остаётся живым. Recovery имеет одинаковый публичный ответ для unknown/known email, но внутренние DB/delivery failures наблюдаемы без раскрытия secrets.

Нельзя держать SQL transaction на время SMTP/provider call. Outbox/inbox фиксируют намерение/событие и повторяемую обработку. После restore до открытия трафика принудительно инвалидировать все восстановленные sessions/challenges и выполнить billing reconciliation; нельзя доверять старому auth version из backup как защите от отката времени.

Цена решения — indexed SQL validation на защищённых запросах и session ledger; нагрузку измеряем в 6/14. Оптимизация, позволяющая принимать только cache, требует нового ADR с явной задержкой revocation и не является базовым профилем.

## Производительность и переиспользование

Redis остаётся частью архитектуры: распределённые limits и feature-owned кеширование данных, для которых явно допустима устарелость. Наличие кеша не отменяет актуальную проверку session/status/version/permissions базового профиля. Security-критические решения не принимаются по устаревшему cached grant. Кешировать только измеренные дорогие чтения; не дублировать SQL session lookup в Redis без доказанного выигрыша.

Взаимодействие хранилищ принадлежит фиче session; PostgreSQL и Redis adapters реализуют малые consumer-owned interfaces, app только собирает зависимости. Не строить общий repository framework, скрытый fallback или обязательный JWT/microservices профиль. Methods, access и billing сохраняют независимые границы.

Сначала определить нагрузочный профиль: число активных сессий, защищённые requests/s, login/reset rates, P95/P99 latency, resource budget и допустимые ошибки. Замерять отдельно hash verification, SQL session validation, refresh и Redis limiter, в том числе на нескольких API instances. Пределы pools/concurrency, deadlines, frequency refresh, bounded cache fills и очередь запросов должны предотвращать перегрузку; численные параметры выбираются по результатам, а не обещанию «любая нагрузка».

Cache-only validation — отдельное, по умолчанию отключённое расширение только после необходимости, подтверждённой измерениями, и согласования нового ADR. Он обязан определить максимально допустимую задержку отзыва, возраст SQL-проверки, не продлеваемый cache reads/refill из старого snapshot, надёжную invalidation с retry, stale-fill/refresh races, clock skew, Redis failover/restore и bounded отказ/fallback. TTL сам по себе не доказывает границу отзыва. Чувствительные записи всегда повторно проверяют актуальный доступ в SQL-транзакции; устаревшие permissions не обходят их. Ни 5 секунд, ни другая задержка сейчас не являются согласованным default.

Redis persistence/replication не считается доказательством немедленного отзыва: старый cache после восстановления не должен возвращать доступ. Cache failures не вызывают неограниченную лавину SQL fallback; операции, требующие Redis limits, остаются fail-closed. В базовом профиле protected validation уже использует SQL и не переключается на Redis при SQL failure.

Переиспользование означает отдельный экземпляр на проект с независимыми данными/secrets/namespaces. Единый Auth/SSO для нескольких проектов требует отдельного профиля приложений/clients/audience и изоляции прав/лимитов по ADR 001; не включается автоматически вместе с Redis или копированием шаблона.
