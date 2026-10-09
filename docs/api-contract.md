# Текущий API-контракт

Состояние на 9 октября 2026. Источник маршрутов — `internal/transport/http/router`; DTO и error mapping — transport каждой фичи. Спецификация — Swagger 2.0, не OpenAPI 3.

| Метод и путь | Успех | Ошибки |
| --- | --- | --- |
| GET `/ping` | 200, текст `pong` | Legacy endpoint, не readiness |
| GET `/health/live` | 200, `status` | Проверка процесса |
| GET `/health/ready` | 200, `status` | 503 без деталей зависимости |
| POST `/api/v1/auth/register/email` | 201, `userID`, Set-Cookie, queued verification | 400 validation, 409 email conflict, 429 limits, 503 limiter failure, 500 internal_error |
| POST `/api/v1/auth/login/email` | 200, `status`, Set-Cookie | 400 validation/invalid_credentials, 500 internal_error |
| POST `/api/v1/auth/change-password` | 200, **`Status`** | 401 session, 403 email_not_verified, 503 SQL gate, 400 input/credential errors, 404 not_found, 500 internal_error |
| POST `/api/v1/auth/email/resend` | 202, `status: accepted` | 400 input, 429 limits, 503 dependency |
| POST `/api/v1/auth/email/verify` | 200, `status: ok` | 400 input/invalid_verification, 429 limits, 503 dependency |
| POST `/api/v1/dev/send-mail` | 200, `status` | Только dev; 400 input, 500 send_failed |

Ошибка содержит `code` и `message`. Поле `Status` смены пароля сохранено с заглавной буквой для совместимости; это не желаемый новый стандарт. Изменение на `status` требует отдельного решения по контракту. Swagger теперь отражает текущий JSON, а не изменяет его.

JSON endpoints требуют `Content-Type: application/json`, не более 1 MiB, один JSON value и отсутствие неизвестных полей. Ошибки декодирования возвращают 400 `invalid_json`. Required-поля описаны в DTO metadata и проверяются обработчиками; metadata не заменяет runtime validation.

Email нормализуется trim/lower, до 255 байт, без display name и обёртки. Новый пароль — 8–128 байт, содержит букву, цифру и uppercase-букву. Это текущая политика, не рекомендация для всех продуктов. В Swagger длины не выражены через minLength/maxLength: байты UTF-8 не равны числу символов. При login новый-password policy повторно не применяется.

## Cookie и безопасность

Сессия передаётся через `__Host-session`: Secure, HttpOnly, Path=/, без Domain, SameSite=Lax, с Expires. Token отсутствует в JSON. Cookie требует HTTPS; браузерный dev-вход через обычный HTTP не считается проверенным рабочим профилем. Swagger 2.0 не поддерживает нативную cookie authentication scheme: не выдаём её за Bearer/API key, требование описано у операции. Swagger UI — отдельный интерфейс с Basic Auth при включении, не бизнес-API и не доказательство исправности cookie login.

Change-password защищён session middleware: отсутствующая или отвергнутая сессия даёт 401. Затем SQL verified-email gate проверяет активный account и подтверждение login email: 403 при отказе, 503 при dependency failure. Login с неверными credentials даёт существующий 400, не 401; неподтверждённый пользователь может войти. Общие CSRF/Origin/fresh-auth, account status/auth-version/session-ledger enforcement и атомарный SQL revoke пока не реализованы; отсутствие этих защит блокирует production release. SameSite=Lax не заменяет CSRF policy. Confirmation/resend и доставка — [verification](email-verification.md).

Ошибки политики нового пароля при change-password сейчас не включены в client error mapping и дают 500 `internal_error`. Это зафиксированный дефект lifecycle: исправить явно в 5/6 с tests и обновлением Swagger, не менять незаметно в документационном этапе.

## Проверки

`task check` включает contract tests: dev/prod routes против спецификации, DTO JSON names/types/required, body/schema refs/media types, статусы и JSON ответов через реальный router, cookie attributes и client error codes. Service/session/mail заменены тестовыми реализациями — это не PostgreSQL/Redis/provider E2E.

`task swagger` обновляет артефакты. `task check:api` генерирует JSON/YAML/Go во временный каталог, сравнивает все три файла с сохранёнными и удаляет только временные файлы. Включён в CI; новый shell-скрипт не добавлен. Это generation drift и целевые структурные contract checks, не полный внешний Swagger-validator, security audit или browser test.

Проверка SQL up/down/up выполнена на отдельном PostgreSQL в 4.1 и повторена после добавления verification в 5.1; рабочая БД не менялась. Future reset/logout/Telegram/MFA/payment endpoints не публикуются в Swagger как уже работающие.
