# Telegram как дополнительный фактор

## Граница текущего подэтапа — A6.3m.6d.1

Реализован внутренний Bot API adapter в `internal/integrations/telegram/bot`, отдельно от существующего OIDC-входа. Принят после Luna V3: task check/lint0 и package race/count1 PASS, manifest10/10 и cleanup подтверждены. Привязка пользователя в БД, активация фактора, вход, публичный webhook и настройки пока не подключены. Приём `/start` адаптером не создаёт пользователя, identity, MFA binding или сессию.

Протокол сверён по [Telegram Bot API](https://core.telegram.org/bots/api) и [private deep links](https://core.telegram.org/bots/features#deep-linking) через Context7 и официальный источник. OIDC Client Secret не является Bot API token. Новая библиотека не требуется: используется стандартный Go HTTP client.

## Bot API adapter

- `NewCredentials` принимает отдельный Bot API token, проверяет безопасную форму и положительный ID из его префикса. Значение скрыто из обычного форматирования; parsing префикса само по себе не доказывает identity бота.
- `Client.Check` вызывает только `https://api.telegram.org/.../getMe` и сверяет реальный bot ID с credentials, `is_bot` и пригодный username. Только успешный ответ создаёт `Bot`, используемый для ссылки и webhook parser.
- Один `Client` может обслуживать разные credentials без отдельных connection pools. У owner ограничены in-flight calls (1–64), соединения, ожидание ответа (5s), headers и body (32KiB); очередь ожидания и автоматические повторы отсутствуют. `Close` отменяет активные calls и закрывает idle connections.
- Адрес API фиксирован. Redirect и environment proxy не используются; TLS минимум1.2. Ошибки HTTP/URL/Telegram description не возвращаются наружу: Bot API token находится в URL path и не должен попасть в ошибки/логи. Техническая ошибка, неправильные credentials, blocked channel и занятый клиент различаются безопасными локальными ошибками.
- `SendCode` принимает положительный user ID до52 значимых бит и ровно8 ASCII-цифр. Отправляется обычный текст с `protect_content=true`, без parse mode и paid broadcast. Успех требует ответа именно из private chat указанного пользователя. Защита от forwarding не предотвращает ручное копирование кода или снимок экрана.

## Входящий private start

`NewWebhook` получает проверенный `Bot` и отдельный случайный webhook secret: canonical base64url от32 случайных байт (43 символа). `DecodeStart` принимает значения `X-Telegram-Bot-Api-Secret-Token` и reader тела:

1. Ровно один правильный header проверяется через constant-time сравнение digest до чтения тела. Это shared-secret authentication поверх HTTPS, не цифровая подпись Telegram. Публичный транспорт, настройка `setWebhook` и секреты проекта будут подключены отдельно.
2. Body ограничен16KiB. Переиспользуются существующие JSON duplicate-key/depth/UTF-8/trailing-data проверки; новые поля Telegram не ломают совместимость.
3. Принимается только свежий обычный `message` из private chat: положительный `from.id`, `is_bot=false`, `chat.id=from.id`, непустой message ID. Forwarded, anonymous/sender-chat, via-bot и business messages не используются. Допуск времени: не старше5m, не более30s в будущем.
4. Команда ровно `/start <binding>`, где binding — canonical base64url от32 случайных байт. `Bot.StartURL` строит фиксированную ссылку `https://t.me/<verified_username>?start=<binding>`.
5. Результат — bot/user/update ID и binding для будущей транзакционной проверки. Username, email, OIDC subject и произвольный JSON клиента не определяют владельца Auth-аккаунта. Unsupported updates дают `ErrIgnored`, не MFA proof.

Parser не хранит состояние и не обеспечивает single-use сам по себе. Дедупликация `update_id`, срок/consume binding, project/session/auth_version/config revision и browser confirmation обязательны в .6d.2 до публичного подключения. Нельзя считать каждый повтор доставки webhook новым подтверждением. Проверять порядок updates по одному глобальному last-ID также нельзя: доставки могут повторяться и приходить не по порядку.

## Следующие подэтапы

### A6.3m.6d.2 — подготовка и подтверждение канала

Минимальный сценарий: текущая browser/password session со свежим password proof и требуемым текущим factor proof создаёт короткоживущий случайный intent. SQL authority принадлежит проектной БД, Redis — scoped admission. `/start` даёт только candidate private channel; код из этого чата подтверждается в исходной browser session. Открытая/пересланная ссылка сама не привязывает канал. Pending intent ограничен пользователем/назначением и TTL; сохраняются verifier/digest, не plaintext код. Перед сетевым вызовом SQL transaction/locks освобождаются.

Проверить locks/constraints и однократность, stale/revoked source session, auth/config version, expiry/guessing/replay, race, channel ownership и cross-project/cross-bot substitution. Идентификаторы проекта/владельца берутся из доверенной сборки и source session; bot user ID — из аутентифицированного update. Не выводить его из Telegram OIDC `sub`, совпадения имён или email. Отдельный secret purpose и guarded Bot API settings нужны до сохранения реальных credentials. Bot ID меняется — старые bindings не перенаправляются на нового бота автоматически.

### A6.3m.6d.3 — lifecycle и policy

Явное разрешение проекта, opt-in пользователя, хранение enrolled/preferred методов и запреты несовместимых переходов. Подготовленный канал ещё не включённый фактор. Активация/смена/удаление требуют действующих proofs, SQL version/permission checks, аудита и отзыва credentials; обязательный последний фактор не удаляется. Потеря канала не допускает тихий fallback. Сохраняются TOTP/recovery и административные strict-proof гарантии.

### A6.3m.6d.4 — login, delivery и публикация

Для первого выпуска выбран password primary; Telegram primary + Telegram second factor не считается независимой MFA и запрещён. Остальные сочетания допускаются только после отдельной оценки. Telegram должен иметь собственный сохранённый method/assurance, не превращаться в strict TOTP/recovery proof. Cookie/native/JWT/refresh/introspection сохраняют фактический метод.

Переиспользовать существующие session/challenge/admission/lifecycle владельцы. Delivery требует явных bounded retries/idempotency и project budgets; не выполнять синхронные повторы в горячем request path, не добавлять новый worker автоматически ради симметрии. Перед выбором outbox/доставки оценить существующий scheduler и требования протокола. Публичные routes/Swagger/secure transport доступны только после readiness и настоящей двухпроектной SQL/HTTP/Redis/fault/recovery приёмки; внешние bot credentials и реальный Telegram sign-off отдельно. UI требует отдельного согласования пользователя.

## Проверки .6d.1

Подготовлены TLS HTTP adapter tests и webhook unit tests: destination/payload, bot/recipient mismatch, redirect, malformed/duplicate/oversized JSON, API401/403/429/503, безопасные ошибки без token, input bounds, shared capacity/cancellation/close; webhook secret до чтения, private identity, stale/future/forward/business/edited updates, canonical binding и чужой secret.

Main выполнил formatter/source review. Отдельный чат Luna выполнил `task check` (exit0, lint0) и `go test -race -count=1 ./internal/integrations/telegram/bot` (exit0) на неизменяемом V3 снимке; manifest10/10 подтверждён, временные cache/server/transport ресурсы очищены. SQL/Redis/schema/API не менялись; их прежние gates не повторяются ради этого adapter-only подэтапа. Реальных Telegram/бота/секретов нет; внешняя доступность, доставка, webhook TLS ingress и MFA не объявляются проверенными.

V1/V2 lint findings и исправления сохранены в [history](../planning/history.md). Финальный V3 `/private/tmp/auth-telegram-mfa-bot-v3.14fggzk7` принят; checked Close находится в HTTP caller, ошибка закрытия проверяется через Client.Check. Два локальных lint exceptions объясняют transport-owner lifetime и отмену per-request context при shutdown; глобальные правила не отключены. Публичные SQL/MFA prerequisites этим подэтапом не закрыты.
