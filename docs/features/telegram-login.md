# Вход через Telegram

## Реализовано в A3.2-local

Используется Authorization Code Flow с PKCE S256 и nonce, не legacy widget/HMAC и не Mini Apps initData. Только scope `openid`, default RS256. Протокол и фиксированные endpoints — [официальный Telegram Login](https://core.telegram.org/bots/telegram-login). Нет запроса UserInfo, email/phone/profile не запрашиваются и не используются для auto-merge.

1. Frontend отправляет POST `/api/v1/auth/telegram/start` с разрешённым Origin и credentials/cookie support. Ответ содержит `authorizationUrl`; браузер переходит по нему. Backend выставляет Secure/HttpOnly/SameSite=Lax `__Host-telegram-flow`, Path=/, без Domain.
2. В Redis на 5 минут сохраняется flow: digest state, digest browser binding, зашифрованные PKCE verifier/nonce. Используется существующий encryption key с отдельным purpose `telegram-login:v1`, без нового root secret. Лимиты применяются до создания flow.
3. Telegram возвращает браузер на GET `/api/v1/auth/telegram/callback?code=...&state=...`. Для cross-site redirect здесь не нужен Origin: защитой служат cookie binding, случайный single-use state, PKCE и nonce. Произвольный GET без правильного flow не создаёт сессию. Не переносить эту exception на другие изменяющие ручки.
4. Lua атомарно проверяет browser binding и потребляет flow. Неверный binding не уничтожает чужой flow; один победитель из параллельных callback. Backend обменивает code через Basic auth + client_id + PKCE, проверяет подпись/issuer/audience/azp/expiry/iat/nonce.
5. Account resolver возвращает владельца issuer/subject или создаёт его, если разрешена регистрация. Creation audit пишется в той же SQL transaction. Existing account/status/version проверяются; session service повторно проверяет актуальность при выдаче. В браузер возвращается только существующий `__Host-session`; ответ `{"status":"ok"}` без Telegram tokens. Flow cookie очищается только при успехе.

UI ещё нет: callback сейчас возвращает JSON, не dashboard redirect. Linking к existing account не реализован; существующий password user с похожими данными автоматически не объединяется с Telegram user. Это обычный пользовательский вход, не fresh password proof и не административное разрешение; MFA добавляется по A5 до admin access.

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

Live Telegram login/browser/nonce echo, multi-instance/fault/load и UI не проверены без operator credentials и зарегистрированного callback. Security scan не прошёл: сообщил о 12 достижимых findings стандартной библиотеки Go 1.27.1; требуется отдельное обновление toolchain и повторная проверка до release. Не считать локальный flow production acceptance.
