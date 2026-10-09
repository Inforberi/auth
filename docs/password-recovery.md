# Восстановление пароля

Этап 5.2, 9 октября 2026. Реализация находится в `internal/auth/methods/password`, SQL-сессии — в `internal/auth/session/repository/postgres`. UI и сохраняемые настройки остаются задачами 14.4s–14.4u.

## API и сценарий

1. `POST /api/v1/auth/forgot-password`, JSON `email`. Ответ 202 `accepted` одинаков для существующего, неизвестного и заблокированного аккаунта; ограничения дают 429, недоступность зависимости — 503.
2. Worker отправляет письмо со ссылкой на frontend из `PASSWORD_RESET_URL`. Frontend получает token из ссылки и показывает форму нового пароля; GET ссылки сам ничего не меняет.
3. `POST /api/v1/auth/reset-password`, JSON `token`, `newPassword`, `confirmPassword`. Успех — 200 `ok` и очистка cookie. Неверный/просроченный/использованный token, несовпадение паролей или нарушение password policy — 400; лимиты — 429; технический сбой — 503.

После reset нужно войти заново. Он не подтверждает email и не создаёт сессию. Change-password тоже отзывает все сессии, включая текущую, и очищает cookie. Ошибка политики нового пароля теперь возвращает 400 `password_policy`, не 500.

## Хранение и атомарность

Token — 32 случайных байта, canonical base64url; в challenge хранится SHA-256 digest. Одновременно действует один challenge на пользователя, повторная выдача имеет SQL cooldown 1 минуту. После cooldown новый challenge заменяет старый. Challenge привязан к текущей `auth_version`, активному аккаунту и сроку действия.

Одна SQL-транзакция потребляет challenge, меняет hash, повышает `auth_version`, отзывает все сессии, удаляет остальные reset-запросы и пишет специализированный audit. Любой сбой, включая audit, откатывает всё. Параллельное потребление допускает ровно один успешный reset.

PostgreSQL — источник действительности сессии. Login передаёт версию, прочитанную вместе с hash; создание сессии повторно проверяет её под блокировкой пользователя. Старый пароль не позволяет создать сессию после reset. Middleware проверяет status/version/revocation/idle и absolute expiry в SQL, conditional refresh не воскрешает отозванную сессию. Недоступность SQL не разрешает доступ: 503, не fallback в Redis.

Прежний Redis session adapter больше не подключён в app; автоматического импорта старых сессий нет. При переходе на SQL ledger пользователи входят заново. Общие CSRF/fresh-auth, rotation, административная блокировка, session HTTP API и полная приёмка этапа 6 ещё впереди.

## Доставка и конфигурация

Payload очереди зашифрован AES-GCM существующим `EMAIL_OUTBOX_KEY`, с отдельным authenticated purpose `password-reset:v1`; verification payload имеет другой purpose. Ключ не возвращается API и не логируется. При ротации нужно согласованно обработать обе очереди, иначе старые payload не расшифруются.

SQL lease 30 секунд, `SKIP LOCKED`, SMTP deadline 20 секунд, максимум 5 попыток и backoff 30/60/120/240 секунд. После успеха/исчерпания попыток payload удаляется; cleanup expired/invalid-version challenges выполняется работающим worker. После crash возможна повторная доставка; exactly-once SMTP не обещается. Старое уже взятое письмо может уйти после замены challenge, но его token недействителен.

Новых env не добавлено. `PASSWORD_RESET_TOKEN_TTL` — 1m–1h; `PASSWORD_RESET_URL` — доверенный frontend URL без userinfo/query/fragment, в production HTTPS. SMTP использует существующие настройки и обязательный production STARTTLS. Runtime secrets и политика через UI вводятся в конце, не сейчас.

Redis limits: forgot 10/IP/min + 3/email/15min; reset 10/IP/min + 100/global/min. Ключи purpose-scoped HMAC, без открытых адресов/IP; Redis failure закрывает операцию. Peer IP берётся из socket, не пользовательского X-Forwarded-For. Reset hashing ограничен двумя параллельными задачами на процесс; нагрузочная настройка и login/register hashing остаются 6.4.

## Проверено и что осталось

`task check` — unit/HTTP/contract tests и lint; `task check:api` — воспроизводимость Swagger. На отдельном PostgreSQL 18.6 `TestPostgresSchema` проверил up/down/up, replacement/cooldown, expiry/replay, concurrent consume, audit rollback, revocation, stale issuance/refresh и atomic change-password. SMTP delivery в этих тестах — test double; Redis recovery failure проверен unit-тестом, не полным recovery E2E.

Внешняя SMTP доставка, browser HTTPS, реальные Redis fault scenarios всего recovery flow, нагрузка и production deployment не проверены. Рабочая БД и `.env` не менялись. Изменена исходная `000001`: уже применённая схема требует отдельно согласованного переноса, не down/reset. Далее — 5.3, session HTTP API.
