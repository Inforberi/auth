# Текущий API-контракт

Состояние на 16 октября 2026. Источник маршрутов — `internal/transport/http/router`; DTO и error mapping — transport каждой фичи. Спецификация — Swagger 2.0, не OpenAPI 3.

| Метод и путь | Успех | Ошибки |
| --- | --- | --- |
| GET `/ping` | 200, текст `pong` | Legacy endpoint, не readiness |
| GET `/health/live` | 200, `status` | Проверка процесса |
| GET `/health/ready` | 200, `status` | 503 без деталей зависимости |
| POST `/api/v1/auth/register/email` | 201, `userID`; required: `verificationRequired=true`, без session cookie; optional/disabled: session cookie. Disabled не ставит автоматическое verification mail | 400 validation, 403 registration_disabled/Origin, 404 method_disabled, 409 email conflict, 429 limits, 503 limits/policy/deadline, 500 internal_error; ошибка не доказывает rollback аккаунта |
| POST `/api/v1/auth/login/email` | 200, `status`, Set-Cookie, либо 202 MFA challenge без session | 400 validation/invalid_credentials, 403 email_not_verified/Origin, 404 method_disabled, 429 limits, 503 dependency/policy, 500 internal_error |
| POST `/api/v1/admin/auth/login/email` | 202, MFA challenge + browser cookie, без session; завершение через `/api/v1/auth/mfa/login/complete` | Permanent password + verified credential email + current admin authority + enrolled MFA; Origin, общий password/MFA budget; 400 validation/invalid_credentials, 403 Origin, 429 limits, 503 dependency, 500 internal_error; без MFA route 404. [Контракт](../features/auth-settings.md#административный-вход--a62a-local) |
| POST `/api/v1/auth/mfa/recovery/start` | 200, `status=operator_approval_required`, requestId/secret/uri/expiresAt, без session | Opt-in MFA_RECOVERY_ENABLED + MFA_ENABLED; existing primary challenge/browser cookie, Origin/no-store; 400 invalid_json/invalid_mfa, 403 Origin, 429 limits, 503 dependency, disabled route 404 |
| POST `/api/v1/auth/mfa/recovery/complete` | 200, codes один раз, очистка старых cookies, без session | JSON requestId/challenge/code + browser cookie/current operator approval/new TOTP; atomic factor/codes/version/revoke/audit/notice. 400 invalid_json/invalid_mfa, 403 Origin, 429 limits, 503 dependency, disabled route 404 |
| POST `/api/v1/auth/email-otp/request` | 202, status accepted и browser-bound flow cookie, optional profile | 400 invalid_json/invalid_email, 403 Origin, 429 limits, 503 dependency; только существующий active verified password email |
| POST `/api/v1/auth/email-otp/confirm` | 200, status ok и обычная session cookie | 400 invalid_email_login/invalid_json, 403 Origin, 429 limits, 503 dependency; восемь цифр, TTL, пять неверных попыток, single-use; не MFA/fresh password proof |
| POST `/api/v1/auth/telegram/start` | 200, authorizationUrl и flow cookie, optional profile | 403 invalid_origin, 429 rate_limited, 503 temporarily_unavailable; disabled route отсутствует |
| GET `/api/v1/auth/telegram/callback` | 200, status; login выставляет session cookie, link сохраняет исходную session | 400 invalid_login, 403 fresh_auth_required, 409 identity_conflict, 429 rate_limited, 503 temporarily_unavailable; single-use browser binding |
| POST `/api/v1/auth/telegram/link` | 200, authorizationUrl и bound flow cookie | 401 session, 403 invalid_origin/fresh_auth_required, 429 limits, 503 dependency; verified permanent password profile |
| DELETE `/api/v1/auth/telegram/link` | 204, отзыв всех sessions, очистка cookie | 400 invalid_login, 401 session, 403 invalid_origin/fresh_auth_required, 409 last_login_method, 429 limits, 503 dependency |
| POST `/api/v1/auth/google/start` | 200, authorizationUrl и Google flow cookie, optional | 403 Origin, 429 limits, 503 dependency |
| GET `/api/v1/auth/google/callback` | 200, status; login выставляет общую session, link сохраняет исходную | 400 invalid_login, 403 fresh_auth_required, 409 identity_conflict, 429 limits, 503 dependency |
| POST `/api/v1/auth/google/link` | 200, authorizationUrl и Google bound flow cookie | 401 session, 403 Origin/fresh_auth_required, 429 limits, 503 dependency |
| DELETE `/api/v1/auth/google/link` | 204, отзыв всех sessions и очистка cookie; Telegram identity остаётся | 400 invalid_login, 401 session, 403 Origin/fresh_auth_required, 409 last_login_method, 429 limits, 503 dependency |
| POST `/api/v1/auth/change-password` | 200, **`Status`**, очистка cookie, отзыв всех сессий | 401 session, 403 email_not_verified, 503 SQL gate, 400 input/credential/password_policy errors, 404 not_found, 500 internal_error |
| POST `/api/v1/auth/email/resend` | 202, `status: accepted` | 400 input, 429 limits, 503 dependency |
| POST `/api/v1/auth/email/verify` | 200, `status: ok` | 400 input/invalid_verification, 429 limits, 503 dependency |
| POST `/api/v1/auth/email/change` | 202, `status: accepted`, optional profile | 400 input/invalid_email_change, 401 session/fresh_auth_required, 403 invalid_origin, 409 email_change_pending, 429 limits, 503 dependency |
| POST `/api/v1/auth/email/change/confirm` | 200, `status: ok`, отзыв сессий и очистка cookie, optional profile | 400 input/invalid_email_change, 401 fresh_auth_required, 403 invalid_origin, 429 limits, 503 dependency |
| POST `/api/v1/auth/email/change/report` | 200, `status: ok`, отмена или блокировка, очистка cookie, optional profile | 400 input/invalid_email_change, 403 invalid_origin, 429 limits, 503 dependency |
| POST `/api/v1/auth/email/change/recover` | 200, `status: ok`, новый пароль/прежний email, отзыв сессий и очистка cookie, optional profile | 400 invalid_json/invalid_account_recovery/password_mismatch/password_policy/same_password, 403 invalid_origin, 429 limits, 503 dependency |
| POST `/api/v1/auth/forgot-password` | 202, `status: accepted` | 400 input, 429 limits, 503 dependency |
| POST `/api/v1/auth/reset-password` | 200, `status: ok`, очистка cookie, отзыв всех сессий | 400 input/invalid_reset/password_mismatch/password_policy, 429 limits, 503 dependency |
| GET `/api/v1/auth/me` | 200, `userId`, `sessionId` | 401 unauthorized, 503 dependency |
| GET `/api/v1/auth/sessions` | 200, `sessions`, optional `nextCursor` | 400 invalid_session_id, 401 unauthorized, 503 dependency |
| POST `/api/v1/auth/session/rotate` | 204, новый токен только в cookie; прежний недействителен | 401 unauthorized, 403 invalid_origin, 503 dependency |
| POST `/api/v1/auth/reauthenticate/password` | 200, `validUntil`, новый токен только в cookie | 400 invalid_json, 401 unauthorized/fresh_auth_required, 403 invalid_origin, 429 rate_limited, 503 dependency |
| POST `/api/v1/auth/logout` | 204, отзыв текущей сессии, очистка cookie | 401 unauthorized с очисткой stale cookie, 403 invalid_origin, 404 session_not_found при гонке expiry, 503 dependency |
| POST `/api/v1/auth/logout-all` | 204, отзыв всех собственных сессий, очистка cookie | 401 unauthorized, 403 invalid_origin, 503 dependency |
| DELETE `/api/v1/auth/sessions/{id}` | 204, отзыв собственной сессии; cookie очищается при отзыве текущей | 400 invalid_session_id, 401 unauthorized, 403 invalid_origin, 404 session_not_found, 503 dependency |
| POST `/api/v1/dev/send-mail` | 200, `status` | Только dev; 400 input, 500 send_failed |

Ошибка содержит `code` и `message`. Поле `Status` смены пароля сохранено с заглавной буквой для совместимости; это не желаемый новый стандарт. Изменение на `status` требует отдельного решения по контракту. Swagger теперь отражает текущий JSON, а не изменяет его.

JSON endpoints с телом требуют `Content-Type: application/json`, не более 1 MiB, один JSON value и отсутствие неизвестных полей. Ошибки декодирования возвращают 400 `invalid_json`. Required-поля описаны в DTO metadata; предметные проверки выполняет service, metadata не заменяет runtime validation. Новые session endpoints не принимают JSON body.

Email нормализуется trim/lower, до 255 байт, без display name и обёртки. Новый пароль — 8–128 байт, содержит букву, цифру и uppercase-букву. Это текущая политика, не рекомендация для всех продуктов. В Swagger длины не выражены через minLength/maxLength: байты UTF-8 не равны числу символов. При login новый-password policy повторно не применяется.

## Регистрация и повтор после сбоя

Аккаунт, login email, credentials, профиль, verification challenge/outbox и audit создаются одной SQL-транзакцией. Ошибка внутри неё откатывает все записи; повтор после подтверждённого rollback может создать аккаунт. Предварительный ExistsByEmail экономит hashing для занятого адреса, но не заменяет UNIQUE: гонку выигрывает одна транзакция, остальные возвращают 409 `email_already_exists` без сессии/Set-Cookie и без повторного письма.

Сессия создаётся отдельным шагом после account commit. Сбой session/token generation не удаляет созданный аккаунт и не отменяет поставленное verification-письмо. При потерянном ответе возможна уже созданная сессия, raw token которой клиент не получил; её сроки/retention остаются обычными. Не пытаемся удалять пользователя или делать автоматический login по конфликту email.

Timeout, 500/503 или потеря HTTP/COMMIT-ответа не позволяют клиенту определить, был ли account commit. Можно повторить registration, но запрос не идемпотентен в смысле воспроизведения прежнего 201/cookie: если аккаунт уже создан, получим 409. Дальше — отдельный login с паролем; 409 не доказывает владение адресом и не разрешает выдачу session. Если пароль неизвестен — стандартное восстановление. UI должен различать «аккаунт создан» и «вход выполнен», не повторять регистрацию бесконечно и не обещать откат при dependency error.

Локальная приёмка 6.6: 16 service-запросов одного нормализованного email принудительно проходят preflight до CreateUser; один success, 15 domain conflicts и одна verification/session. Проверены rollback после queue, account commit с моделируемой потерей ответа, session failure до commit и session commit с моделируемой потерей ответа, последующий retry/login и отсутствие cookie в ошибочном HTTP-ответе. SQL commit настоящий; ошибка reply инжектируется тестовым adapter после него, не реальным сетевым proxy. Test hash/limiter заменяют Argon2/Redis; это не нагрузка или network failover acceptance.

## Cookie и безопасность

Приглашения — opt-in INVITATIONS_ENABLED (default false). POST `/api/v1/auth/invitations/activate` принимает token/password/confirmPassword и требует точный Origin. Success 200 `status: ok` без Set-Cookie; 400 invalid_json/invalid_invitation/password_mismatch/password_policy, 403 invalid_origin, 429 rate_limited (Retry-After 60), 503 temporarily_unavailable. GET не активирует аккаунт. Provisioning/admin endpoints отсутствуют; [контракт и границы](../features/invitations.md).

Смена email — opt-in `EMAIL_CHANGE_ENABLED` (default false); disabled runtime не подключает четыре маршрута, Swagger описывает включённый профиль. Request требует session + текущий пароль + подтверждённый нынешний login email. Confirm/report/recover требуют разных одноразовых токенов и точного Origin; GET не меняет state. Report после завершения блокирует account без email rollback/session/unblock и ставит recovery-письмо старому verified email. Recover текущего password-профиля требует новый пароль, возвращает прежний адрес входа и отменяет старые полномочия до снятия защитной блокировки; admin/deleted bypass отсутствует. Внешняя приёмка 5.5e остаётся release gate. TTL, retained contacts и ограничения — [email change](../features/email-change.md).

Session API 5.3 доступен и до подтверждения email. `me` возвращает только идентификаторы, не профиль. Список содержит до 50 активных сессий, `current`, даты, User-Agent/IP; сортировка по `(created_at,id)` DESC. `before=nextCursor` продолжает список без OFFSET. ID — самостоятельный lowercase UUID, не token/hash. Неверный/чужой cursor — 400; чужой/неизвестный/неактивный target для отзыва — одинаковый 404. Все ответы этих ручек, включая ошибки auth/Origin, имеют `Cache-Control: no-store`.

Для всех auth mutations, включая login/register/reset/email verification, и dev send-mail обязателен один точный HTTPS `Origin` из `AUTH_ALLOWED_ORIGINS` (через запятую, без пробелов и путей). Отсутствующий, `null`, чужой или повторный Origin — 403 `invalid_origin` до обработчика/session lookup; Host/X-Forwarded-Host не задают доверие. GET/HEAD без Origin поддерживают CLI; переданный Origin проверяется. CORS opt-in `AUTH_CORS_ENABLED=false`: включение разрешает только точный allowlist и credentialed same-site HTTPS frontend, не меняя SameSite=Lax. OPTIONS поддерживает GET/POST/DELETE и Content-Type, не выдаёт session/permissions; все auth ответы no-store. [Профили, HTTPS и границы приёмки](../operations/browser-security.md).

Управление сессиями повторно проверяет caller/status/version/expiry под user row lock в SQL-транзакции. Logout-all повышает `auth_version`, блокируя stale issuance; ошибка audit откатывает отзыв. 503 не очищает cookie как будто logout завершён. Logout при отсутствующем/просроченном/отозванном cookie возвращает 401 и очищает cookie; неизвестная зависимостная ошибка остаётся 503. SameSite не заменяет проверку Origin.

Ротация — явный POST с текущим cookie и разрешённым Origin, без body и без токена в JSON; ответы no-store. Атомарно заменяет verifier в существующей SQL session: UUID, owner/version, created_at и idle/absolute deadlines сохраняются. Middleware ротации и logout проверяет доступ без sliding refresh, не выполняя лишнюю запись перед заменой/отзывом. Только одна параллельная замена старого verifier успешна; старый cookie не принимается после commit, grace period нет. Ротация не является fresh-auth и не подтверждает пароль/MFA. Ошибка не меняет cookie, чтобы проигравший запрос не очистил cookie победителя. Browser-клиент должен сериализовать ротации и согласовать их с защищёнными запросами/refresh между вкладками: поздний ответ с прежним Set-Cookie может затереть новый cookie, хотя старый токен не возвращает серверный доступ. Потеря успешного ответа требует нового login; автоматические retry со старым cookie не восстанавливают токен. Настоящая browser-приёмка остаётся открытой.

5.4 не добавляет HTTP endpoints. Blocked/deleted не участвует в credential lookup и session validation. Если аккаунт блокируется или его version меняется между чтением credentials и выдачей сессии, login возвращает существующий 400 `invalid_credentials` без cookie, а не 500; зависимости не маскируются под неверные credentials. Change-password также отклоняет inactive credential lookup/transaction без изменения пароля. Block/unblock реализован внутренним account service с atomic revoke/audit; `ActorID` не даёт права администратора. Admin HTTP transport будет включён только после permissions/MFA/fresh-auth/CSRF, deletion/retention — отдельно в 5.6.

Сессия передаётся через `__Host-session`: Secure, HttpOnly, Path=/, без Domain, SameSite=Lax, с Expires. Token отсутствует в JSON. Cookie требует HTTPS; браузерный dev-вход через обычный HTTP не считается проверенным рабочим профилем. Swagger 2.0 не поддерживает нативную cookie authentication scheme: не выдаём её за Bearer/API key, требование описано у операции. Swagger UI — отдельный интерфейс с Basic Auth при включении, не бизнес-API и не доказательство исправности cookie login.

### Повторное подтверждение пароля

POST `/api/v1/auth/reauthenticate/password` принимает JSON `{"password":"..."}` с текущим cookie и allowed Origin. Проверяет пароль shared bounded Argon2 и Redis IP/user/project budgets, затем атомарно заменяет verifier текущей сессии, записывает server-side `password_verified_at` и audit. Повторная SQL-проверка owner/status/version/hash/revocation/expiry защищает результат Compare от смены credentials или отзыва во время hashing. Raw token только в новом cookie; JSON содержит `validUntil`, не пароль/токен. Ошибка не меняет cookie, не создаёт подтверждение и не сообщает внутренние ошибки. Ответы no-store; при 429 Retry-After=60.

`SESSION_FRESH_AUTH_TTL=5m` — окно подтверждения, bounds 1m–15m; не срок сессии и не rate limit. Session ID/created_at и idle/absolute deadlines сохраняются; окно в ответе не выходит за текущую session expiry. Только explicit reauthentication устанавливает marker; обычный login/registration не получают его автоматически. Normal sliding refresh/rotation marker не обновляют. Proof привязан к данной session/version, не к пользователю целиком; будущие OAuth/Telegram/MFA не считаются подтверждением пароля. Proof не даёт permissions, не доказывает MFA и не заменяет проверки внутри чувствительной SQL transaction.

Email change — первый потребитель: можно передать текущий пароль непосредственно в request как раньше либо опустить его после успешной reauthentication. При отсутствии пароля SQL transaction проверяет marker и свежесть (`now >= verified_at+TTL` означает истечение; future timestamps отклоняются). Переданный неправильный пароль всегда отклоняется, даже при свежем marker. Прямое подтверждение внутри email request разрешает только этот request и не устанавливает общий marker без token rotation. Server guards действуют независимо от UI. Ротация/reauthentication после создания email-change intent инвалидирует прежнюю исходную session hash для его confirmation; согласовывать действия до запроса смены email, не делать повторную ротацию между request и confirm.

Как при обычной rotation, browser-клиент должен согласовать параллельные запросы/refresh между вкладками; lost successful response требует нового login, старый токен не имеет grace period. Реальный browser flow, MFA и административные permissions остаются последующими задачами.

Cookie token — canonical base64url 32 байт без padding (43 символа); неправильная форма отклоняется 401 до SQL. Login: Redis IP/email/global budget до SQL/hash, 429 rate_limited с Retry-After 60, недоступность limiter/общего hash budget — 503 temporarily_unavailable. Общий HTTP admission может вернуть 503 с Retry-After 1 на любой route кроме liveness; readiness сохраняет status=unavailable. Requests имеют bounded context; криптографическое вычисление не прерывается посередине. Refresh достигнутого absolute expiry не делает запись или Set-Cookie; concurrent CAS не сокращает expiry. Настройки и ограничения — [performance](../operations/performance.md).

Change-password сначала проверяет Origin, затем session middleware: отсутствующая или отвергнутая сессия даёт 401, недоступность SQL — 503. Затем SQL verified-email gate проверяет активный account и подтверждение login email: 403 при отказе, 503 при dependency failure. Login с неверными credentials даёт существующий 400, не 401; неподтверждённый пользователь может войти. SQL session ledger проверяет status/auth-version/revocation и сроки, reset/change-password атомарно отзывают сессии. Origin/CORS и password fresh-auth реализованы локально; MFA и полная browser/fault release приёмка ещё открыты. SameSite=Lax не заменяет CSRF policy. Confirmation/resend и доставка — [verification](../features/email-verification.md).

Ошибки политики нового пароля при change/reset-password возвращают 400 `password_policy`. Reset не подтверждает email и не создаёт сессию; после смены пароля требуется новый login. Контракт и ограничения — [password recovery](../features/password-recovery.md).

## Временный пароль

Optional temporary-password профиль добавляет POST `/api/v1/auth/temporary-password/login` и `/complete`: первый возвращает только setup token/expiresAt и status=password_change_required без cookie, второй атомарно устанавливает постоянный пароль и отзывает временные credentials без session/email verification. Обычный login следует после complete. RequireOrigin/no-store, canonical token, fail-closed Redis и общие bounded budgets; expired/replayed/blocked/unknown authority — 400 invalid_temporary_password. Internal creation/reissue не опубликованы как admin endpoints; безопасная operator выдача требует permissions/MFA/fresh-auth/CSRF. [Контракт](../features/temporary-passwords.md).

## Проверки

`task check` включает contract tests: dev/prod routes против спецификации, DTO JSON names/types/required, body/schema refs/media types, статусы и JSON ответов через реальный router, cookie attributes и client error codes. Service/session/mail заменены тестовыми реализациями — это не PostgreSQL/Redis/provider E2E.

`task swagger` обновляет артефакты. `task check:api` генерирует JSON/YAML/Go во временный каталог, сравнивает все три файла с сохранёнными и удаляет только временные файлы. Включён в CI; новый shell-скрипт не добавлен. Это generation drift и целевые структурные contract checks, не полный внешний Swagger-validator, security audit или browser test.

Проверка SQL up/down/up выполнена на отдельном PostgreSQL и повторена для identity audit в A3.2; рабочая БД не менялась. Telegram — local-tested optional flow, live staging впереди. Future MFA/payment endpoints не публикуются в Swagger как уже работающие.

## Telegram login

Optional POST `/api/v1/auth/telegram/start` требует allowed Origin, возвращает authorizationUrl и HttpOnly browser binding cookie. GET `/api/v1/auth/telegram/callback` — исключение только для provider redirect: single-use state/cookie/PKCE/nonce заменяют Origin-проверку этого flow. Login создаёт обычную session и выставляет `__Host-session`, без JWT/token в JSON. POST `/telegram/link` требует verified permanent password account и fresh password proof; link-callback сохраняет исходную session и UUID. DELETE `/telegram/link` требует оставшийся рабочий парольный метод, отзывает все sessions и очищает cookie. Ошибки не очищают текущую session; при disabled profile routes отсутствуют. Live acceptance login/link/unlink отложена перед подключением UI. [Конфигурация, ошибки и ограничения](../features/telegram-login.md).

## Google login

Optional Google использует тот же OIDC flow и SQL-сессии, но отдельные routes/cookie/Redis prefix/purpose и budgets: POST `/api/v1/auth/google/start`, GET `/api/v1/auth/google/callback`, POST/DELETE `/api/v1/auth/google/link`. Owner — canonical Google issuer + subject, без auto-merge по email. Link/unlink требуют verified permanent password и fresh proof; presence другой identity не расширяет last-method policy. [Контракт и ENV](../features/google-login.md).
