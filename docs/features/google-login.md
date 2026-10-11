# Вход через Google — A3.4b-local

Optional backend: Google Authorization Code/OIDC с PKCE S256 и nonce. Выключен по умолчанию. Использует имеющиеся go-oidc v3.21.0/oauth2 v0.36.0, Redis, account identities и SQL-сессии; новых зависимостей, таблиц и workers нет. Реальный вход с credentials/браузером ещё не проверен.

## Подключение

Создать OAuth client типа Web application в Google Cloud Console, настроить consent screen/test users и зарегистрировать **точный** HTTPS callback из GOOGLE_OIDC_REDIRECT_URI. Затем передать Client ID/Secret серверу и включить GOOGLE_LOGIN_ENABLED. Client Secret не попадает в UI-запросы, Swagger, Git или логи; runtime secret settings появятся в A6.

| ENV | Default | Значение |
| --- | --- | --- |
| GOOGLE_LOGIN_ENABLED | false | Подключает четыре routes и provider client |
| GOOGLE_REGISTRATION_ENABLED | false | Разрешает создавать новый UUID после verified Google proof |
| GOOGLE_OIDC_CLIENT_ID | пусто | Web client ID, заканчивающийся на .apps.googleusercontent.com |
| GOOGLE_OIDC_CLIENT_SECRET | пусто | Секрет web OAuth client |
| GOOGLE_OIDC_REDIRECT_URI | sample HTTPS /api/v1/auth/google/callback | Без query/fragment/userinfo; exact registered callback |
| GOOGLE_LOGIN_IP_ATTEMPTS_PER_MINUTE | 30 | Общие start/callback/link/unlink attempts одного IP |
| GOOGLE_LOGIN_PROJECT_ATTEMPTS_PER_MINUTE | 1000 | Общие attempts провайдера по всем экземплярам проекта |

Start + callback расходуют минимум две попытки, это admission budgets, не максимальный API RPS. Disabled профиль не требует credentials, не делает provider network requests и не подключает routes. Переключение ENV требует перезапуска.

## API и браузер

| Метод | Требования | Успех |
| --- | --- | --- |
| POST /api/v1/auth/google/start | Разрешённый Origin | 200 authorizationUrl + flow cookie |
| GET /api/v1/auth/google/callback?code=…&state=… | Single-use state и cookie того же браузера | 200 status=ok; login выдаёт session, link — нет |
| POST /api/v1/auth/google/link | Origin, текущая session, verified permanent password, fresh password proof | 200 authorizationUrl + flow cookie |
| DELETE /api/v1/auth/google/link | Те же Origin/session/fresh требования; рабочий password method остаётся | 204; auth_version увеличивается, все сессии отзываются |

Start/link не принимают target UUID, email или subject в JSON. Ответ: `{"authorizationUrl":"https://accounts.google.com/o/oauth2/v2/auth?…"}`. Frontend переходит по нему; callback пока возвращает `{"status":"ok"}`, не redirect на dashboard.

Flow cookie `__Host-google-flow`: Secure/HttpOnly/SameSite=Lax/Path=/, без Domain, TTL 5 минут. Google и Telegram cookies независимы. Один Google flow на браузер; параллельные вкладки могут заменить cookie. Callback не требует Origin при обычном redirect без этого заголовка, но должен предъявить правильные state/binding/code; другие mutations по-прежнему требуют Origin.

При login backend очищает только Google flow cookie и выдаёт обычный `__Host-session`. Provider access/ID tokens не сериализуются клиенту и не сохраняются как sessions. Старую SQL-сессию новый login автоматически не отзывает.

Ошибки callback не изменяют cookies: 400 invalid_login для replay/expiry/bad binding/claims/unknown identity/registration disabled; 403 fresh_auth_required для link; 409 identity_conflict или last_login_method; 429 rate_limited + Retry-After: 60; 503 temporarily_unavailable. Session middleware дополнительно возвращает 401, Origin middleware — 403 invalid_origin. Выключенные routes отсутствуют, Swagger всё равно содержит optional контракт.

После одноразового consume, provider error или потерянного ответа начинать новый start/link: flow не восстанавливается. Callback query содержит code/state — не включать их в access logs/analytics; shared security headers задают Referrer-Policy.

## Проверка личности

Фиксированные endpoints взяты из [Google discovery](https://accounts.google.com/.well-known/openid-configuration): authorization accounts.google.com/o/oauth2/v2/auth, token oauth2.googleapis.com/token, keys www.googleapis.com/oauth2/v3/certs. Нельзя передать произвольный issuer/token/JWKS URL через ENV или пользовательский запрос.

Scope только openid: email/profile/UserInfo не нужны текущему ownership-сценарию. Server exchange предъявляет client secret в POST и PKCE verifier. Проверяются RS256 signature, issuer, audience, azp, exp, iat, nonce и непустой subject; insecure skips не используются.

Google допускает issuer accounts.google.com или https://accounts.google.com. Поддерживаемый verifier проверяет этот Google-specific вариант; в account resolver передаётся **canonical https://accounts.google.com + subject**, чтобы один Google аккаунт не получал два UUID из-за формы issuer. Другие issuer не нормализуются произвольно. Правила — [официальный Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect).

Владелец определяется по issuer + subject, никогда по email. Если registration включена, создаётся отдельный active UUID/profile/identity, без выдуманного email или password credentials. Если выключена, возможен только login уже связанной identity. Заблокированный/удалённый owner не создаётся заново; session issuance проверяет текущий SQL status/version.

## Привязка и последняя возможность входа

Password-пользователь сначала вызывает POST /api/v1/auth/reauthenticate/password и получает обновлённую session cookie. Затем POST /google/link; до callback нельзя rotating session. Flow содержит owner UUID и hash исходной session, callback требует ту же cookie и актуальный SQL fresh proof. Повторной проверки пароля нет.

Link не регистрирует UUID и не выдаёт session, не зависит от GOOGLE_REGISTRATION_ENABLED. SQL гарантирует одного владельца issuer/subject и одну identity каждого provider/account. Занятая identity не перезаписывается; same-owner retry не добавляет audit.

Unlink удаляет только Google identity. Telegram identity остаётся, но после повышения auth_version старые sessions отозваны. Текущий verified permanent password обеспечивает оставшийся рабочий вход. **Наличие другой identity в таблице не считается доказательством рабочего включённого метода**; external-only users пока не управляют methods через этот API, даже с двумя providers. Provider/MFA step-up и A6 settings lockout policy — отдельные задачи. Email OTP не расширяет unlink policy: сейчас сам требует permanent-password email.

Google login не даёт password fresh proof, MFA, roles или административный доступ. OIDC authentication не заменяет permissions.

## Переиспользование и нагрузка

Общие service/domain/Redis/HTTP scenarios перенесены из Telegram в methods/oidc. У Google/Telegram остаются собственные config, fixed provider settings и Swagger routes; transport только делегирует сценарий. Это общий код двух действующих providers, не plugin framework.

Telegram Redis prefix/cipher purpose/cookies/API сохранены. Google использует auth:google и google-login:v1 на существующем root key. Scoped encrypted state/binding/PKCE/nonce + atomic Lua consume не смешивают providers; service дополнительно отклоняет proof другого issuer до SQL resolution.

Shared bounded HTTP client: только точные HTTPS token/JWKS URLs, без redirects/произвольных query/hosts; headers до 16 KiB, body до 64 KiB, ID token до 16 KiB, 5s network deadline, до 16 connections/host и 8 idle/host. JWKS переиспользуется verifier, discovery/UserInfo на каждый login не вызываются. Client lifetime отменяется и idle connections закрываются при app shutdown/failed assembly.

Redis operations до 3s, flow до 10s; Redis failure fail-closed. SQL pool и session mechanism прежние. Суммировать network/Redis/SQL budgets по всем enabled providers и replicas; реальные capacity и GC/leaks проверяются в A8, не заявляются по unit tests.

## Приёмка

Локально проверены crypto claims и legacy/canonical Google issuer, provider mismatch до SQL, disabled/registration flags, Origin/session gates, cookie isolation/duplicate query, shared service link/unlink, ошибки и Swagger DTO/routes.

Disposable Redis: encryption/TTL/binding/replay, один winner из 16 callback consumers, отдельные provider keys/budgets. Disposable PostgreSQL: Google и Telegram с одинаковым subject остаются разными keys, link ownership/provider uniqueness, unlink/session revocation/version, last-method protection и обычная SQL session без выдуманного email/пароля.

Реальный Google consent/callback/PKCE/nonce flow, faults/JWKS rotation, browser и mixed/multi-instance load ещё открыты вместе с Telegram перед UI/release. БД/schema/dependencies и реальные ENV/secrets этим этапом не менялись.
