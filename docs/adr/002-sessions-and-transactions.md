# ADR 002: durable отзыв сессий и одноразовые операции

Статус: принято, 6 октября 2026. Реализация: 4, 5.1–5.4, 6.1–6.3, 8.4, 13.1.

## Решение

Opaque session token генерируется криптографически; raw token хранится только в защищённой browser cookie. В серверном ledger — verifier/digest, user UUID, auth version, сроки, revoked state и authentication context. PostgreSQL — источник истины. На каждом защищённом запросе проверяется актуальный ledger и user status/version; Redis cache не заменяет эту проверку. Отзыв имеет силу для проверок, начавшихся после SQL commit; чувствительная запись повторно проверяет доступ внутри транзакции, блокируя конфликтующую смену версии/отзыв. Уже выполненный внешний эффект отозвать задним числом нельзя.

Single logout отзывает SQL session; logout-all/password reset/change/block повышают user auth version транзакционно вместе с изменением credentials/status. Redis cleanup best-effort после commit, а не security boundary. Refresh изменяет лишь существующую активную session условной атомарной операцией; не воскрешает revoked session. `now >= deadline` означает истечение; idle expiry/Redis TTL/cookie не выходят за absolute deadline. Token rotation не продлевает absolute срок.

Authentication context фиксирует серверно подтверждённые методы/время входа, fresh-auth и MFA; данные provider/client не становятся административными permissions. MFA/fresh-auth проверяются backend для чувствительных действий, отдельно от sliding TTL.

## Challenges, audit и доставка

Verify/reset/OTP/link challenges связаны с purpose/owner/intent, ограничены сроком и попытками; хранят verifier, не raw secret. Conditional consume и изменение аккаунта/credentials/auth version/security audit происходят одной SQL-транзакцией. Два concurrent consume дают ровно один успех. Недоставленное письмо не подтверждает identity. Повторная доставка использует outbox с ограниченными retry, сроком и dedup; resend policy явно инвалидирует прежний challenge.

Когда outbox должен хранить secret для отправки письма, payload защищается шифрованием с отдельным operational key, коротким retention и исключением из логов. Не обещаем exactly-once email; гарантируем безопасное повторение и одноразовое потребление. Доступ к audit ограничен, credentials/tokens/provider secrets в него не записываются. Критический audit/outbox write failure откатывает соответствующую domain transaction.

## Отказы и восстановление

Недоступна SQL/не подтверждён status/version — защищённый запрос отклоняется как dependency failure, а не принимается по cache. Redis недоступен — auth/challenge операции, зависящие от limiter или session инфраструктуры, временно недоступны; не разрешаем неограниченные попытки и не вводим скрытый fallback. Независимый liveness остаётся живым. Recovery имеет одинаковый публичный ответ для unknown/known email, но внутренние DB/delivery failures наблюдаемы без раскрытия secrets.

Нельзя держать SQL transaction на время SMTP/provider call. Outbox/inbox фиксируют намерение/событие и повторяемую обработку. После restore до открытия трафика принудительно инвалидировать все восстановленные sessions/challenges и выполнить billing reconciliation; нельзя доверять старому auth version из backup как защите от отката времени.

Цена решения — indexed SQL validation на защищённых запросах и session ledger; нагрузку измеряем в 6/14. Оптимизация, позволяющая принимать только cache, требует нового ADR с явной задержкой revocation и не является базовым профилем.
