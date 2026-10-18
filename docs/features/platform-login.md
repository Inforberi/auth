# Вход оператора платформы — MP2.3 operator profile

18 октября 2026. Добавлен отдельный **opt-in профиль одного platform runtime**, переиспользующий существующий Auth. Подключено [чтение каталога проектов](platform-projects-api.md); management mutations, диспетчер нескольких проектов и UI ещё не реализованы. Текущий standalone остаётся профилем по умолчанию. [Realm/permissions](platform-operators.md), [Redis/crypto scope](realm-isolation.md), [план](../planning/multi-project.md).

## Конфигурация и запуск

| Переменная | Назначение |
| --- | --- |
| `PLATFORM_ENABLED` | По умолчанию false; true выбирает операторскую assembly вместо обычной проектной |
| `PLATFORM_REALM_ID` | Canonical nonzero UUID из `platform.operator_realm`, полученный оператором из доверенной БД |
| `PLATFORM_ORIGIN` | Точный canonical HTTPS origin панели, без wildcard/path/query |

Нужна **новая отдельная платформенная БД**. В ней offline migration owner применяет Auth000001, затем platform000001/000002; существующие Task migration-команды сами этого не делают. Миграция operator realm отвергает использованную Auth БД. После этого оператор создаёт отдельную LOGIN runtime-роль и адаптирует [grants template](../../deploy/platform-runtime-grants.sql) под свои имена БД/роли. Приложению передаётся runtime `DATABASE_URL`, не owner/provisioner credential. Само приложение БД/роли не создаёт.

`EMAIL_OUTBOX_KEY` — отдельный платформенный ключ, не копия ключа проекта. Scope строится из `platform` + trusted realm UUID и сверяется с dependencies. Первый владелец создаётся через scoped setup этого профиля, не legacy/project bootstrap. Автоматического импорта/переинициализации/перешифрования старой установки нет.

Обязательны `MFA_ENABLED=true`, direct server TLS (`HTTP_TLS_CERT_FILE`/`HTTP_TLS_KEY_FILE`), единственный `AUTH_ALLOWED_ORIGINS`, равный PLATFORM_ORIGIN, и выключенный CORS. `PASSWORD_RESET_URL` должен принадлежать этому origin. SMTP, password/session/retention/capacity задаются прежними operational ENV; SMTP в минимальном профиле используется из deployment config, не через опубликованный settings UI.

JWT/native, Google/Telegram/email OTP, приглашения/temporary/contact-change features в этом профиле запрещены. Публичные password/register endpoints не монтируются независимо от public policy настроек. Swagger/project settings/users/access routes также не публикуются. Примеры ENV сохраняют PLATFORM_ENABLED=false; установка новых ENV не включает их автоматически.

TLS termination с plaintext upstream пока не поддержан: HTTP-запросы и чужой Host получают404. Прокси должен сохранять configured Host и использовать TLS до backend; X-Forwarded-Host не выбирает realm. Настоящие DNS/certificates/ingress этим локальным тестом не настроены.

## Проверки БД до маршрутов

`operator.Repository.CheckRuntime` выполняется до assembly writes. Требует ожидаемый initialized marker либо разрешённый first setup. Отвергает superuser/CREATEDB/CREATEROLE/BYPASSRLS, membership привилегированных/owner ролей, SET ROLE соединение, владение БД/schema/таблицами и DDL права в auth/platform/public. Проверяет необходимые platform SELECT/INSERT/marker-column UPDATE grants и отсутствие audit rewrite/marker rewrite/restore-audit mutation прав. Привилегии проверяются по отдельности, не как «хотя бы одна из списка».

Runtime использует прежний Auth DML/retention контракт, но не получает blanket platform DML/default grants, schema CREATE или provisioning права. Это startup guard, не замена текущих SQL session/permission guards внутри операций. Root wrapping/signing keys для будущих проектов, executor и pool registry ещё впереди.

## Маршруты

| Сценарий | Маршруты |
| --- | --- |
| First owner | POST `/api/v1/setup/start`, `/api/v1/setup/complete`; только при INITIAL_SETUP_ENABLED и с X-Setup-Token |
| Password + MFA | POST `/api/v1/admin/auth/login/email` → POST `/api/v1/auth/mfa/login/complete` |
| Password recovery | POST `/api/v1/auth/forgot-password`, `/api/v1/auth/reset-password` |
| Каталог платформы, чтение | GET `/api/v1/platform/projects`, `/api/v1/platform/projects/{id}`; current platform.projects.read, no session refresh, без binding/secrets |
| Свои сессии | GET `/api/v1/auth/me`, `/api/v1/auth/sessions`; POST logout/logout-all; DELETE `/api/v1/auth/sessions/{id}` |
| Сроки/смена сессии | POST `/api/v1/auth/session/activity`, `/api/v1/auth/session/rotate` |
| Fresh password | POST `/api/v1/auth/reauthenticate/password`, `/api/v1/auth/change-password` |
| Существующий MFA | GET `/api/v1/auth/mfa/status`; POST `/api/v1/auth/mfa/step-up`, `/api/v1/auth/mfa/recovery-codes/regenerate`, `/api/v1/auth/mfa/totp/replacement`, `/api/v1/auth/mfa/totp/replacement/confirm` |

Пользовательские Handler/DTO/Swagger descriptions переиспользуются без второго password/MFA стека. Полученный session cookie остаётся `__Host-session`, Secure/HttpOnly/SameSite=Lax/Path=/, без Domain; MFA binding cookie — также host-only. Setup не создаёт сессию. Login сначала выдаёт только challenge; password reset отзывает все старые сессии, сохраняет MFA/права и требует повторного входа. Logout возвращает прежний204.

Профиль не публикует MFA disable/enrollment. [Потеря всех факторов](platform-recovery.md) подключается только при `MFA_RECOVERY_ENABLED=true` и проверенных отдельных offline grants: POST `/api/v1/auth/mfa/recovery/start`, `/api/v1/auth/mfa/recovery/complete`, с независимым CLI approval между ними. По умолчанию выключено. Это не повторный bootstrap/публичный MFA bypass. Имеющиеся TOTP recovery-коды для входа работают. Проектная cookie сама не становится платформенной: SQL pool/marker/origin фиксированы; полный тест двух runtime/БД остаётся MP7.

## Проверено

- Final `task check` PASS/lint0; targeted race App/config/router/setup/operator-domain PASS. Opt-in SQL fixture при unit/race без ENV пропускается.
- `TestOperatorProfileSQLHTTPS` **PASS1.50s**, PostgreSQL18.6/Redis8.2.6/Linux arm64. Настоящее соединение от отдельной ограниченной LOGIN роли, marker/missing INSERT/excess audit UPDATE/marker ID UPDATE/schema CREATE guards; local TLS HTTP setup+email code+TOTP, password+MFA recovery code, scoped SQL authority, unknown cookie401, reset через encrypted SQL outbox+fake mailbox, immediate session revoke, повторный login+MFA, logout204/revoke, restart с выключенным setup.
- TLS — `httptest` server/client с проверкой тестового сертификата, request Host задаётся отдельно. Mailer — bounded in-memory test mailbox, не внешний SMTP. Unit проверяют allowlist/Host/plaintext/forwarded-host/Origin/foreign scope и config incompatibilities. Это не реальный browser/ingress/fleet sign-off.
- Fixture schemas/LOGIN роль/Redis keys удалены; DB15 count0; новая auth_platform_test удалена без FORCE, исходная auth сохранена. PostgreSQL/Redis возвращены в initial stopped; scratch удалён. Рабочие ENV/secrets/данные не менялись.

Аварийная scoped CLI и lost-all-factors SQL/HTTP drill выполнены следующим блоком [MP2.4](platform-recovery.md). NOT RUN: настоящий deployment/TLS certificate/ingress/browser/SMTP/аутентификатор/independent identity verification, полная матрица двух проектов и SQL grants upgrades, fleet/rotation/load/GC/max RPS. MP2/pre-ui gates целиком не закрыты. Далее — transitions и management/catalog/bridge.
