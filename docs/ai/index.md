# Карта проекта

Обязательные правила — [AGENTS.md](../../AGENTS.md), ближайший шаг — [current-task](current-task.md). Ниже маршрутизация, не перечень обязательного чтения. Выбрать нужную тему, прочитать связный раздел с ограничениями и проверить код.

| Тема | Источник | Где искать |
| --- | --- | --- |
| План и результаты | [implementation](../planning/implementation.md), [roadmap](../planning/roadmap.md), [history](../planning/history.md) | В implementation — текущий выпуск A1–A8; history читать только для нужного прошлого решения |
| Архитектура и запуск | [architecture](../architecture.md), [ADR](../adr/) | `cmd/auth`, `internal/app`, `internal/config`, `internal/server/http` |
| API и ошибки | [contract](../api/contract.md), [руководство интегратора](../auth-guide.md) | `internal/transport/http/router`, `httpx`, фичевые `transport/http`; generated — `docs/api/generated` |
| Схема и транзакции | [schema](../schema.md), [ADR 002](../adr/002-sessions-and-transactions.md) | `migrations`, фичевые `repository/postgres` |
| Sessions/security | [auth-security](../planning/auth-security.md), [ADR 002](../adr/002-sessions-and-transactions.md) | `internal/auth/session`, router; для конкретного сценария — его service/repository |
| Native refresh — storage | [refresh-storage](../features/refresh-storage.md), [ADR 004](../adr/004-jwt-access-profiles.md) | token/domain/refresh, service/refresh_family, repository/postgres/refresh_*; caller-owned SQL primitives, runtime owner/native HTTP ещё впереди |
| JWT — ключи и выдача | [jwt-keys](../features/jwt-keys.md), [jwt-exchange](../features/jwt-exchange.md), [jwt-access](../planning/jwt-access.md), [ADR 004](../adr/004-jwt-access-profiles.md) | internal/auth/token/{signing,service,repository,settings,transport/http}, app/auth/token.go, router/token.go, pkg/authjwt; native/refresh/online middleware — J4/J5 |
| Политика входа/settings | [auth-settings](../features/auth-settings.md) | `internal/auth/settings`, `internal/app/auth`, `internal/config` |
| SMTP settings/rotation | [smtp-settings](../features/smtp-settings.md) | Settings: `smtp*`, `app/auth/smtp.go`, `infra/mailer` |
| Google/Telegram settings/rotation | [provider-settings](../features/provider-settings.md) | Settings: `provider*`, `app/auth/provider_settings.go`, OIDC flow/MFA provider version, `integrations/oidc` shared owner |
| Роли/permissions | [roles-permissions](../features/roles-permissions.md) | `internal/access` |
| Каталог разрешений | [access-catalog](../features/access-catalog.md) | `internal/access/settings`, `cmd/access-catalog`, `internal/app/access` |
| Список/карточка пользователей | [user-directory](../features/user-directory.md) | Account: `user_directory`, `list_users`, `read_user` |
| Статус, удаление, retention | [account-deletion](../features/account-deletion.md) | `internal/auth/account`, config, app lifecycle |
| Сохраняемые сроки очистки | [retention-settings](../features/retention-settings.md) | Settings: `retention*`, account worker; batch/interval остаются ENV |
| Первый super-admin | [initial-setup](../features/initial-setup.md) | Account: `setup*`; не lost-admin recovery |
| Аварийное восстановление пароля | [admin-recovery](../features/admin-recovery.md) | `cmd/admin-recovery`, password: `operator_recovery*`, `deploy/recovery-grants.sql` |
| Приглашения/provisioning | [invitations](../features/invitations.md) | Account: `provision*`/`invitation_*`, password: `activate_invitation*` |
| Временный пароль | [temporary-passwords](../features/temporary-passwords.md) | Password: `temporary_*` |
| Обычный password recovery | [password-recovery](../features/password-recovery.md) | Password: forgot/reset/change |
| Email verification | [email-verification](../features/email-verification.md) | Account: `verification_*`, delivery |
| Первая почта external-only | [email-binding](../features/email-binding.md) | Account: `email_binding*` |
| Смена email/защитный recovery | [email-change](../features/email-change.md) | Account: `email_change_*`, password: `protected_recovery*` |
| MFA | [mfa](../features/mfa.md) | `internal/auth/mfa`, emailotp: `reauthentication_*` |
| Потеря всех MFA-факторов | [mfa-recovery](../planning/mfa-recovery.md), [runbook](../operations/mfa-recovery-acceptance.md) | MFA recovery, `cmd/admin-recovery`; не отключение MFA |
| Внешние identities | [external-identities](../features/external-identities.md) | Account: `linked_identity`, `identity_resolution*` |
| Telegram / Google | [telegram](../features/telegram-login.md), [google](../features/google-login.md) | `internal/auth/methods/{telegram,google,oidc}`, `internal/integrations`, app/auth |
| Email OTP | [email-otp](../features/email-otp.md) | `internal/auth/methods/emailotp`, app/auth, delivery runner |
| Origin/CORS/HTTPS/SMTP | [browser-security](../operations/browser-security.md) | HTTP middleware/router, server, `internal/infra/mailer` |
| Угрозы и security boundaries | [threat-model](../threat-model.md), нужный [ADR](../adr/) | Проверить границы затронутого сценария, не только HTTP middleware |
| Нагрузка и ресурсы | [performance](../operations/performance.md) | Hasher/limits, HTTP admission, SQL/Redis, retention/delivery |
| Команды и CI | [режим проверок](../planning/implementation.md#режим-проверок-после-уточнения-пользователя) | `Taskfile.yml`, `.github/workflows/ci.yml`, `deploy` |

Под «Account» понимается `internal/auth/account`, под «Password» — `internal/auth/methods/password`. Путь с `*` — ориентир поиска, не отдельный пакет. Правила инструментов и актуализации — в AGENTS; подробные статусы сюда не копировать.
