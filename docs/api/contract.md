# Текущий API-контракт

Состояние на 11 октября 2026. Источник маршрутов — `internal/transport/http/router`; DTO и error mapping — transport каждой фичи. Спецификация — Swagger 2.0, не OpenAPI 3.

| Метод и путь | Успех | Ошибки |
| --- | --- | --- |
| GET `/ping` | 200, текст `pong` | Legacy endpoint, не readiness |
| GET `/health/live` | 200, `status` | Проверка процесса |
| GET `/health/ready` | 200, `status` | 503 без деталей зависимости |
| POST `/api/v1/auth/register/email` | 201, `userID`, Set-Cookie, queued verification | 400 validation, 409 email conflict, 429 limits, 503 limiter failure, 500 internal_error |
| POST `/api/v1/auth/login/email` | 200, `status`, Set-Cookie | 400 validation/invalid_credentials, 500 internal_error |
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

Проверка SQL up/down/up выполнена на отдельном PostgreSQL в 4.1 и повторена после добавления verification/recovery в 5.1/5.2; рабочая БД не менялась. Future logout/Telegram/MFA/payment endpoints не публикуются в Swagger как уже работающие.
