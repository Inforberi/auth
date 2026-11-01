# Telegram как дополнительный фактор

## Граница текущего подэтапа — A6.3m.6d.1

Реализован внутренний Bot API adapter в `internal/integrations/telegram/bot`, отдельно от существующего OIDC-входа. Принят после Luna V3: task check/lint0 и package race/count1 PASS, manifest10/10 и cleanup подтверждены. Private SQL-подготовка канала принята после Luna V4 в .6d.2a; public binding, активация фактора, вход, webhook и настройки пока не подключены. Приём `/start` адаптером не создаёт пользователя, identity, MFA binding или сессию.

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

## Private подготовка канала — A6.3m.6d.2a (PASS Luna)

Три внутренних сценария `mfa/service.TelegramPreparation`, без HTTP/ENV/реального бота:

- `Request(proof,ip)`: текущая browser/password session, свежий password proof и требуемый текущий MFA proof; временный случайный binding. Возвращаются binding/SQL deadline, не фактор или новый вход.
- `Receive(TelegramStart)`: только доверенная проекция уже аутентифицированного private update из Bot API adapter. Проверяются ожидаемые bot/user/update ID и binding, admission, текущая source session/config. Сохраняются candidate и verifier; зашифрованный код возвращается только внутреннему sender caller. Сетевого вызова под SQL locks нет. Повтор того же update возвращает прежний payload/code без продления TTL, reset attempts или повторного audit; другой sender/update не перезаписывает candidate.
- `Confirm(proof,binding,code,ip)`: только исходная session и текущие proofs; пять ошибочных кодов коммитятся и переживают retry. Успех очищает payload/verifier, помечает intent confirmed и ротирует token только исходной session, возвращая его внутреннему caller для cookie. Session ID, сроки, auth_version/password/MFA proof и права не повышаются. Включённого фактора/identity/новой сессии нет.

Состояние — одна `auth.mfa_telegram_preparations` на Auth user: digest, source session ID и отдельный snapshot token hash/auth_version, bot ID и policy version, candidate Telegram ID/update ID, verifier/encrypted payload, attempts, confirmed marker, created/expiry. TTL1–5m ограничен свежестью source proofs и session deadlines. Confirmed preparation тоже краткоживущая: это доказательство для будущей явной активации .6d.3, не постоянный enrolled factor. Повтор consume не разрешается; новый Request заменяет прежний intent.

FK на session ID удаляет preparation вместе с сессией; индекс FK исключает полный проход при session cleanup. Hash источника не каскадируется при обычной ротации: такой intent становится stale. Только собственный successful Confirm атомарно обновляет snapshot на новый hash. Существующий indexed bounded retention удаляет expired rows; soft account deletion очищает их явно. Unique bot/candidate и bot/update ограничивают конкурирующее владение внутри проектной БД; reclaim касается только истёкшей preparation, никогда будущего enrolled factor.

`auth.mfa_settings.telegram_bot_id` — nullable Bot API identity metadata, не OIDC Client ID или secret. По умолчанию NULL. Вместе с существующим settings.version это SQL authority: на Request/Receive/Confirm строка блокируется FOR SHARE и должна совпасть с server-owned TelegramBotBinding. Bot identity/policy/version change запрещает stale completion. Readiness нельзя подменить клиентским JSON. Private backend настроек .6d.2b принят после Luna V3; до публикации HTTP/сборки/readiness реальные credentials/public routes не подключаются. Любая запись секретов увеличивает settings.version даже при прежнем bot ID.

Crypto требует отдельного project-scoped purpose `telegram-channel:v1`; digest/verifier/payload не переиспользуют OIDC/email purpose. Raw code и replacement token исключены из автоматической JSON-сериализации внутренних результатов. Admission scoped по user/IP/project и update/binding/Telegram ID; Redis errors fail-closed до SQL. Shared fresh-password management guard перенесён из email.go в factor_management.go с семантическим rename без изменения SQL-условий. Генерация8-digit CSPRNG кода переиспользуется email и Telegram через внедрённый token port (реализация TokenManager.GenerateCode), без service→infra import.

Источник000001 up/down изменён без новой миграции; реальная БД не обновлялась. Новому binary нужна обновлённая schema даже при выключенном Telegram: retention обращается к новой таблице. Upgrade существующих БД — отдельный MP6 gate, не обходить отсутствие schema флагом метода. Новых dependencies/workers/очередей/routes/Swagger/ENV не добавлено; cache/capacity/fleet/Telegram delivery этим не измеряются.

Luna V4: manifest29/29, финальный lint0 и formatting-only equivalence V2→V4. Приняты V2 Go tests/architecture и MFA/emailotp/tokengenerate affected race; actual TestTelegramChannelPreparationSchema, TestPostgresSchema, TestEmailFactorPreparationSchema и TestEmailFactorLifecycleSchema с race/count1 на disposable TLS/SCRAM SQL прошли exit0 без SKIP, fixture/cache очищены. Полный task check после whitespace-only правок не повторялся: прежние unit результаты и прочий lint сохранены, затронутый lint проверен отдельно. V1 compile/boundary и V2/V3 style FAIL/исправления сохранены в history. Новые cases: same-session/no proof elevation, duplicate/update/owner/scope substitution, wrong attempts, source token/logout/block/version/expiry/config changes, required/native denial, concurrent one-winner, audit rollback, bounded retention/FK cleanup. Tests не заменяют будущую actual webhook/two-project HTTP/Redis/delivery приёмку .6d.4.

## Настройки Bot API — A6.3m.6d.2b

Private backend принят после Luna V3. `settings/service.TelegramBotSettings` предоставляет `Read`, `Update`, доверенный `Credentials`; HTTP-ручек и app wiring пока нет. Административное чтение возвращает только общий version, botId, username, botTokenSet/webhookSecretSet. Флаги означают наличие сохранённых секретов, а не подтверждение текущей доступности Telegram. `Credentials` предназначен только для внутренних операций: секреты исключены из JSON и скрыты при fmt.

Update принимает текущий Principal, ExpectedVersion, необязательную замену BotToken и RotateWebhookSecret. Пропущенный token сохраняет прежний, пустой отклоняется; отсутствие обоих изменений — авторизованный no-op без сети/записи. Удаление конфигурации пока не публикуется. Перед сетевым вызовом проверяются актуальные session/password/требуемый factor proof, auth.settings.manage и version; preflight завершается COMMIT. User/project budgets используют внедрённый project-scoped limiter, ошибки закрывают изменение. getMe через существующий bounded TLS Bot API client выполняется без SQL locks. Перед сохранением новая транзакция повторно проверяет текущие права/proofs/version и deadline: отзыв сессии/прав либо конкурирующая запись исключают stale commit.

Секреты хранятся отдельно в `auth.telegram_bot_settings`, а не provider_settings/OIDC. Шифрование — два внедрённых project-scoped purpose: `telegram-bot-token:<project>:v1` и `telegram-webhook:<project>:v1`. Envelope дополнительно связывает bot ID и вид секрета; копирование ciphertext между проектами/полями/ботами не даёт рабочих credentials. Common root не означает общий scope. Runtime loader читает согласованный SQL snapshot и fail-closed проверяет расшифровку/метаданные; не кеширует произвольно изменяемые secrets.

Webhook secret генерирует сервер: 32 случайных байта, canonical base64url43. Первая настройка, смена bot ID или явный RotateWebhookSecret создают новый secret. Замена token прежнего бота сохраняет webhook secret, если rotation не запрошена. getMe должен вернуть тот же bot ID, что token; неверные credentials/сбой проверки дают безопасную ошибку без URL/token/body. Проверка конфигурации не вызывает setWebhook и не меняет чужую существующую подписку.

Metadata, ciphertext, общий `auth.mfa_settings.version` и masked audit сохраняются атомарно. Собственного дублирующего revision нет; политика/secret rotation инвалидируют незавершённые привязки через существующую version. session_revision не повышается: изменение конфигурации не подделывает пользовательские proofs. Audit хранит actor/version и masked previous/next, без plaintext/ciphertext; его существующий bounded retention удаляет по security audit policy. Отказ записи audit откатывает весь update.

Подготовлены unit/TLS и actual SQL cases: ограничения доступа, no-op, ротация и stale preparation, смена прав/version/сессии во время getMe, один победитель конкурентной rotation, audit rollback, secret masking/project-purpose isolation/tamper. Luna: V2 Go tests/affected race и все4 actual SQL roots PASS без SKIP; V3 final repository lint0, manifest25/25 и rename-only equivalence. Full task check после rename не повторялся: V2 остановился на единственном G101, устранённом уточнением имени SQL-константы; успешные проверки сохранены. Реальные БД и env/secrets не менялись; source000001 обновлён без новой миграции, MP6 upgrade отдельно.

Перед публикацией .6d.3/.4 нужны lifecycle-защита смены bot identity при enrolled factors, protected settings routes, platform-owner bridge и сборка crypto/лимитов/client lifetime, readiness и webhook registration/ingress. Bot token сам по себе не включает фактор. Нельзя монтировать private service напрямую в публичный HTTP без этих guards. Внешний Telegram, доставка, два project runtimes и capacity остаются отдельными gates; UI отдельно.
