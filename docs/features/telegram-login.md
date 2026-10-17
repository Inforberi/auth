# Вход через Telegram

A6.3c.2-local: [Client ID/Secret — сохраняемые настройки](provider-settings.md), ENV только seed. Изменение secret не требует restart; старые pending OIDC/link/MFA/recovery proofs требуют нового primary login, existing sessions сохраняются. Secret никогда не возвращается в GET/audit/logging. Callback и admission budgets остаются deployment ENV; routes доступны при готовом operational adapter, публичный допуск/регистрация определяются сохранённой Auth policy. Исторические описания первоначального ENV-only подключения ниже не заменяют этот runtime contract.

После A3.4b общие domain/service/Redis/HTTP сценарии находятся в `methods/oidc`, bounded token/JWKS client — в `integrations/oidc`. Telegram сохраняет свои config, fixed endpoints, публичные routes, cookies, Redis prefix и cipher purpose. [Google](google-login.md) использует ту же реализацию с отдельным профилем; другой issuer не разрешает account resolution Telegram flow.

## Реализовано в A3.2-local

Используется Authorization Code Flow с PKCE S256 и nonce, не legacy widget/HMAC и не Mini Apps initData. Только scope `openid`, default RS256. Протокол и фиксированные endpoints — [официальный Telegram Login](https://core.telegram.org/bots/telegram-login). Нет запроса UserInfo, email/phone/profile не запрашиваются и не используются для auto-merge.

1. Frontend отправляет POST `/api/v1/auth/telegram/start` с разрешённым Origin и credentials/cookie support. Ответ содержит `authorizationUrl`; браузер переходит по нему. Backend выставляет Secure/HttpOnly/SameSite=Lax `__Host-telegram-flow`, Path=/, без Domain.
2. В Redis на 5 минут сохраняется flow: digest state, digest browser binding, зашифрованные PKCE verifier/nonce. Используется существующий encryption key с отдельным purpose `telegram-login:v1`, без нового root secret. Лимиты применяются до создания flow.
3. Telegram возвращает браузер на GET `/api/v1/auth/telegram/callback?code=...&state=...`. Для cross-site redirect здесь не нужен Origin: защитой служат cookie binding, случайный single-use state, PKCE и nonce. Произвольный GET без правильного flow не создаёт сессию. Не переносить эту exception на другие изменяющие ручки.
4. Lua атомарно проверяет browser binding и потребляет flow. Неверный binding не уничтожает чужой flow; один победитель из параллельных callback. Backend обменивает code через Basic auth + client_id + PKCE, проверяет подпись/issuer/audience/azp/expiry/iat/nonce.
5. Account resolver возвращает владельца issuer/subject или создаёт его, если разрешена регистрация. Creation audit пишется в той же SQL transaction. Existing account/status/version проверяются; session service повторно проверяет актуальность при выдаче. В браузер возвращается только существующий `__Host-session`; ответ `{"status":"ok"}` без Telegram tokens. Flow cookie очищается только при успехе.

UI ещё нет: callback сейчас возвращает JSON, не dashboard redirect. Обычный login не объединяет password user с Telegram user по похожим данным. Явная привязка описана ниже. Login не является fresh password proof или административным разрешением; MFA добавляется по A5 до admin access.

## Привязка и отвязка: A3.3-local

Привязка доступна account с подтверждённым email и постоянным паролем. Сначала POST `/api/v1/auth/reauthenticate/password`: существующий механизм проверяет пароль, заменяет session cookie и сохраняет password_verified_at. Затем POST `/api/v1/auth/telegram/link` с новым cookie и разрешённым Origin. Повторного Compare пароля нет; срок свежести — существующий `SESSION_FRESH_AUTH_TTL` (по умолчанию 5 минут).

Link-start проверяет SQL fresh proof и сохраняет в зашифрованном Redis flow purpose=link, owner UUID и session hash вместе с PKCE/nonce. Client не выбирает target UUID/subject. Telegram возвращает тот же callback URL; callback должен принести неизменённую исходную session cookie. Missing/duplicate/changed cookie не авторизует привязку. После provider verification SQL transaction повторно проверяет active account, auth_version, непросроченную/неотозванную session и свежесть proof. Это защита от изменений между start и callback, не повторное сравнение пароля.

Пара issuer/subject не перезаписывается и не переносится от другого владельца. UNIQUE `(user_id,issuer)` допускает одну identity данного provider на account и ограничивает рост связей. Повторная привязка той же identity тому же owner — no-op без повторного audit; другая identity/provider owner — 409 identity_conflict. Link-callback возвращает status=ok и очищает только flow cookie: не создаёт новый UUID, не выдаёт и не заменяет session, не выставляет fresh/MFA proof. Public registration flag не нужен для link.

DELETE `/api/v1/auth/telegram/link` удаляет текущую Telegram-привязку пользователя из session context, без произвольного owner в JSON. Нужны Origin, session и fresh password proof. Под user/session locks проверяется, что остаётся постоянный пароль с verified email, без pending provision/temporary password. Email сам по себе и неизвестный будущий provider не считаются способом входа. Успех: unlink + увеличение auth_version + отзыв всех sessions + identity_unlinked audit в одной SQL transaction, ответ 204 и очистка caller session cookie. После этого войти по паролю заново. Ошибка не меняет cookies/ownership; rollback audit возвращает исходные привязку и доступ.

409 last_login_method защищает от потери рабочего входа; 403 fresh_auth_required — отсутствующий/устаревший proof или недоступный account. Start/callback/unlink используют прежние shared IP/global Redis budgets и deadlines, без новых ENV, workers, root secrets или SDK. Сам login path не получил дополнительных SQL проверок. Schema changes только в source 000001: новые audit events и owner/provider UNIQUE, без отдельной миграции или изменения рабочей БД.

Неподтверждённый email не позволяет привязать внешний метод: это препятствует закреплению доступа на предварительно зарегистрированном чужом адресе. External-only account сейчас не может управлять методами без password proof; provider/MFA step-up будет отдельным проверяемым сценарием, обычный Telegram login не заменяет его. После явной отвязки identity свободна: будущая public Telegram registration может создать отдельный UUID, не вернуть связь с прежним аккаунтом. Deleted account без unlink сохраняет прежний ownership reservation.

Login и link используют одну flow cookie: вкладки должны сериализовать start. Старые flows без purpose после обновления отвергаются и истекают за 5 минут; начать flow заново.

## Настройки

По умолчанию routes отключены; нет provider requests или требований к Telegram secrets.

| Env | Назначение |
| --- | --- |
| `TELEGRAM_LOGIN_ENABLED=false` | Включить start/callback |
| `TELEGRAM_REGISTRATION_ENABLED=false` | Разрешить создание нового UUID по неизвестной Telegram identity; existing identity может войти при false |
| `TELEGRAM_OIDC_CLIENT_ID` | Числовой Client ID из BotFather Login Widget |
| `TELEGRAM_OIDC_CLIENT_SECRET` | Client Secret из того же раздела, **не Bot API token** |
| `TELEGRAM_OIDC_REDIRECT_URI` | Полный HTTPS URL `/api/v1/auth/telegram/callback`, без query/fragment; зарегистрировать в BotFather |
| `TELEGRAM_LOGIN_IP_LIMIT=30` | Общий бюджет start + callback на один IP за минуту |
| `TELEGRAM_LOGIN_GLOBAL_LIMIT=1000` | Общий бюджет start + callback на экземпляр проекта за минуту, через общий Redis всех replicas |

Успешный вход обычно расходует две попытки: start и callback. Это защитные budgets, не измеренный RPS. Оба значения положительны и доступны для настройки. Чтобы первый Telegram user мог зарегистрироваться до linking, необходимо отдельно включить регистрацию; при false неизвестная identity получает generic invalid_login.

BotFather должен содержать точный callback URL. Scope nonce echo и реальную конфигурацию клиента подтвердить на staging; missing/mismatched nonce отвергается, insecure fallback отсутствует. Если в BotFather выбран не RS256, этот профиль отклонит token, а не примет алгоритм автоматически.

## Ошибки и ограничения

400 `invalid_login`: неверный/повторный/expired flow, proof или недоступный account. Ошибки token exchange/storage/session dependency возвращают generic 503; 429 содержит Retry-After: 60. Не логируются query/code/state/binding/JWT/client secret или содержимое provider error. Неизвестный/невалидный proof и ошибки JWKS verification сейчас fail-closed как invalid_login; это не подтверждение доступности JWKS.

Flow потребляется **до** обмена code. При timeout, lost reply или ошибке позже начать вход заново; code не повторяется автоматически. Already committed account остаётся существующим и будет найден следующей попыткой, session revocation/version guard не обходится. Не обещаем общей транзакции Redis, Telegram и SQL. Несколько вкладок должны сериализовать start: новая flow cookie заменяет старую, старый flow истекает через 5 минут.

Сетевой клиент принимает только HTTPS fixed Telegram token/JWKS endpoints, без redirects/proxy environment. Request timeout 5s, transport/header/body/connections bounded; JWKS кешируется библиотекой. Flow deadline 10s, Redis operation deadline 3s; пользовательские HTTP/SQL pools/admission остаются прежними. Provider client закрывается при cleanup; unlimited retries/queues/workers не добавлены. Identity audit очищается существующим bounded retention worker по 180-дневной policy.

Схема identity_audit добавлена только в исходную 000001, рабочая БД не менялась. Уже применённой установке потребуется согласованный upgrade, не reset.

## Проверено и что остаётся

Formatter/task check, Swagger generation, race Telegram provider/service/HTTP; signed local HTTPS fixture: signature/algorithm/issuer/audience/azp/expiry/iat/nonce и provider outage. Service/HTTP: порядок gates, single-use concurrency, disabled routes, Origin, duplicate query/cookie rejection, safe cookies/errors. Disposable Redis 8.2: ciphertext, TTL, wrong binding, 16 concurrent consume, tamper/replay, distributed IP/global budgets. Полный PostgreSQL 18.6 up/down/up/race: identity audit/rollback и существующий lifecycle.

Go обновлён до 1.27.2 в go.mod и Dockerfile; CI получает версию из go.mod. Повторный govulncheck: 0 достижимых уязвимостей, 0 imported-package findings. Остаётся module-only [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) в x/crypto/openpgp, который приложение не импортирует; исправленной версии нет. Используемый Argon2 не удаляем вместе с необходимым x/crypto.

Live Telegram login/link/unlink/browser/nonce echo отложены пользователем до подготовки подключения UI. В локальном .env Telegram-настройки отсутствуют; нужны operator Client ID/Secret и зарегистрированный HTTPS callback. Секреты задавать локально, не присылать в чат. Проверить разрешённый Origin, успешные login/link callbacks, replay/changed session/fresh expiry, конфликт owner, logout после unlink и отказ неизвестной identity при выключенной регистрации. Multi-instance/fault/load — A8. Не считать локальный flow production acceptance.
