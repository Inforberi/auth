# Карта проекта

Project lifecycle: [контракт](../features/project-lifecycle.md), `internal/platform/project/domain/transition.go`, `repository/postgres/transition.go`, `migrations/platform/transitions_test.go`; caller-owned transaction после authority locks, atomic audit/receipt. HTTP/executor не подключены.

Multi-project operator foundation: [контракт и ограничения](../features/platform-operators.md), `internal/platform/operator`, `migrations/platform/000002_operators.*`; использует Auth setup, не отдельный login stack.

Opt-in operator Auth: [platform-login](../features/platform-login.md), `app/auth/operator.go`, `router/operator.go`, `config/platform.go`, operator repository `runtime.go`, `deploy/platform-runtime-grants.sql`; один профиль/listener, не fleet dispatcher.

Offline operator recovery: [platform-recovery](../features/platform-recovery.md), `cmd/admin-recovery/realm.go`, operator repository `recovery.go`, `deploy/platform-recovery-grants.sql`; explicit platform UUID и отдельные DB-группы, существующие password/MFA транзакции.

Сборка Auth: `internal/app/auth/app.go` — standalone resources/server; `realm.go` — feature assembly с borrowed dependencies; `run.go` — background lifecycle. Второй realm пока не публикуется.

Redis/crypto scope: [контракт и проверки](../features/realm-isolation.md), `internal/infra/realmscope`, `app/auth/realm_security.go`, feature `repository/redis/*`. Standalone — explicit legacy, не default для новой платформы.

Обязательные правила — [AGENTS.md](../../AGENTS.md), ближайший шаг — [current-task](current-task.md). Ниже маршрутизация, не перечень обязательного чтения. Выбрать нужную тему, прочитать связный раздел с ограничениями и проверить код.

| Тема | Источник | Где искать |
| --- | --- | --- |
| План и результаты | [implementation](../planning/implementation.md), [roadmap](../planning/roadmap.md), [history](../planning/history.md) | В implementation — текущий выпуск A1–A8; history читать только для нужного прошлого решения |
| Архитектура и запуск | [architecture](../architecture.md), [ADR](../adr/) | `cmd/auth`, `internal/app`, `internal/config`, `internal/server/http` |
| Независимые проекты — до UI | [multi-project MP1–MP8](../planning/multi-project.md), [ADR005](../adr/005-independent-projects.md), [каталог](../features/project-catalog.md) | internal/platform/project/{domain,repository/postgres}, migrations/platform; process/project split и admin bridge — ADR005, runtime ещё однопроектный |
| API и ошибки | [contract](../api/contract.md), [руководство интегратора](../auth-guide.md) | `internal/transport/http/router`, `httpx`, фичевые `transport/http`; generated — `docs/api/generated` |
| Схема и транзакции | [schema](../schema.md), [ADR 002](../adr/002-sessions-and-transactions.md) | `migrations`, фичевые `repository/postgres` |
| Sessions/security | [auth-security](../planning/auth-security.md), [ADR 002](../adr/002-sessions-and-transactions.md) | `internal/auth/session`, router; для конкретного сценария — его service/repository |
| Native refresh/logout/API | [native-http](../features/native-http.md), [refresh-storage](../features/refresh-storage.md), [ADR 004](../adr/004-jwt-access-profiles.md) | token/{service,repository/postgres,transport/http}/{refresh,logout}*, App token/native_token, router/token; bounded cleanup — account/{retention,transient_cleanup}, SQL retention_checkpoints |
| Первая API issuance | [native-issuance](../features/native-issuance.md) | password/service/authenticate → token/service/native_password_login/native_login; repository/postgres/native/issuance_audit; policy — config/native_jwt.go, сборка — app/auth/token/native_token |
| Native MFA | [native-mfa](../features/native-mfa.md), [native HTTP](../features/native-http.md) | token/service/native_login, repository/postgres/native_mfa; mfa/service/native_login/login_enrollment и repository/postgres/native_completion/login_*; HTTP — token/transport/http/native_mfa/native_enrollment* |
| Native email OTP | [native-email-otp](../features/native-email-otp.md), [native HTTP](../features/native-http.md) | token/service/native_email_login и methods/emailotp/service/native_login; общий repository/postgres/{request,confirm}, API-only target/proof → issuance/MFA; HTTP — token/transport/http/native_email_* |
| JWT — ключи и выдача | [jwt-keys](../features/jwt-keys.md), [jwt-exchange](../features/jwt-exchange.md), [jwt-access](../planning/jwt-access.md), [ADR 004](../adr/004-jwt-access-profiles.md) | internal/auth/token/{signing,service,repository,settings,transport/http}, app/auth/token.go, router/token.go, pkg/authjwt |
| JWT online authority | [jwt-introspection](../features/jwt-introspection.md) | token/{service,repository/postgres,repository/redis,settings,transport/http}/introspection*, app/auth/token_introspection |
| JWT consumer/middleware | [jwt-consumer](../features/jwt-consumer.md) | pkg/authjwt/{consumer,consumer_transport,jwks_cache,introspection,middleware,permissions,principal}, example_test; Auth TLS wire contract — router/jwt_consumer_contract_test |
| JWT settings/UI contract | [jwt-profile-settings](../features/jwt-profile-settings.md) | settings policy/SQL/HTTP tokenIssuance, read-only tokenProfiles; app/auth/token_deployment; final token/MFA SQL guards |
| JWT security/restore gate | [матрица S1–S10](../operations/jwt-security-acceptance.md), [recovery](../operations/jwt-recovery.md) | password repository jwt_consumer_sql/restore_auth integration tests; deploy/restore-auth-state.sql + scripts/postgres-restore.sh/mock tests; source restore_audit/runtime-grants |
| Локальный HTTPS-стенд | [sandbox](../operations/local-sandbox.md) | Task sandbox:up/down/jwt/jwt:rotation/admin/lifecycle/security, deploy/compose.sandbox*.yml + sandbox-runtime.sql; deploy/sandbox — fixtures и opt-in JWT/rotation/admin/lifecycle/security acceptance; ignored tmp/sandbox, отдельный Compose project auth-sandbox |
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
| Нагрузка и ресурсы | [performance](../operations/performance.md), [HTTP baseline/cleanup](../operations/load-baseline.md), [load/rest](../operations/load-rest.md) | Hasher/limits, HTTP admission, SQL/Redis, retention/delivery; Task sandbox:load/load:rest/cleanup, deploy/sandbox/load*_test.go и cleanup* fixtures/observer |
| Команды и CI | [режим проверок](../planning/implementation.md#режим-проверок-после-уточнения-пользователя) | `Taskfile.yml`, `.github/workflows/ci.yml`, `deploy` |

Под «Account» понимается `internal/auth/account`, под «Password» — `internal/auth/methods/password`. Путь с `*` — ориентир поиска, не отдельный пакет. Правила инструментов и актуализации — в AGENTS; подробные статусы сюда не копировать.
