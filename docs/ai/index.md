# Карта проекта

Начать с [текущего шага](current-task.md), затем выбрать нужную строку ниже. Это навигация, не список обязательного чтения: статусы — в плане, поведение — в коде, доказательства — в history. Правила — [AGENTS.md](../../AGENTS.md).

Пути к исходникам относительно корня репозитория; Auth = `internal/auth`, Project = `internal/platform/project`.

## Проекты и сборка

| Задача | Первичный документ | Код |
| --- | --- | --- |
| План независимых проектов | [MP1–MP8](../planning/multi-project.md), [ADR005](../adr/005-independent-projects.md) | `Project`, `internal/platform/operator` |
| Каталог, создание, состояния | [каталог](../features/project-catalog.md), [read API](../features/platform-projects-api.md), [создание](../features/platform-project-creation.md), [изменения](../features/platform-project-mutations.md), [lifecycle](../features/project-lifecycle.md) | `Project/{domain,service,repository/postgres,transport/http}` |
| Подготовка БД и ключей | [reservation](../features/project-preparation.md), [storage](../features/project-storage-preparation.md), [schema](../features/project-schema-preparation.md), [credentials](../features/project-secrets-preparation.md) | `cmd/project-prepare`, `Project/{storage/postgres,credentials,repository/postgres}`, `deploy/*grants.sql` |
| Onboarding проекта | [подготовка, runtime, SQL admission, activation/recovery и HTTP-профиль](../features/project-onboarding-preparation.md), [первый администратор](../features/initial-setup.md) | `internal/app/auth/project_onboarding*`, `Project/{credentials/onboarding*,repository/postgres/onboarding*,storage/postgres/onboarding*}`, `Auth/account/*/setup*`, `internal/transport/http/router/project_onboarding*` |
| Оператор платформы | [foundation](../features/platform-operators.md), [login](../features/platform-login.md), [recovery](../features/platform-recovery.md) | `internal/platform/operator`, `internal/app/auth/operator*`, `router/operator.go`, `cmd/admin-recovery` |
| Сборка, lifecycle, изоляция | [архитектура](../architecture.md), [realm isolation](../features/realm-isolation.md) | `internal/app/auth/{app,realm,run,realm_security}.go`, `internal/config`, `internal/server/http`, `internal/infra/realmscope` |

## Auth и доступы

| Задача | Первичный документ | Код |
| --- | --- | --- |
| API, ошибки, middleware | [контракт](../api/contract.md), [руководство](../auth-guide.md), [browser security](../operations/browser-security.md) | `internal/transport/http/{router,httpx,middleware}`, фичевые `transport/http` |
| Сессии, транзакции, SQL | [security-план](../planning/auth-security.md), [ADR002](../adr/002-sessions-and-transactions.md), [schema](../schema.md) | `Auth/session`, `migrations`, фичевые `repository/postgres` |
| Password, provisioning | [recovery](../features/password-recovery.md), [offline recovery](../features/admin-recovery.md), [invitations](../features/invitations.md), [temporary](../features/temporary-passwords.md) | `Auth/methods/password`, `Auth/account/*/{provision*,invitation_*}`, `cmd/admin-recovery` |
| Email и внешние входы | [verification](../features/email-verification.md), [binding](../features/email-binding.md), [change](../features/email-change.md), [identities](../features/external-identities.md), [email OTP](../features/email-otp.md), [Google](../features/google-login.md), [Telegram](../features/telegram-login.md) | `Auth/account`, `Auth/methods/{emailotp,google,telegram,oidc}`, `internal/integrations` |
| MFA | [контракт](../features/mfa.md), [recovery-план](../planning/mfa-recovery.md), [приёмка](../operations/mfa-recovery-acceptance.md) | `Auth/mfa`, `Auth/methods/emailotp/service/reauthentication*` |
| Роли и пользователи | [roles](../features/roles-permissions.md), [permission catalog](../features/access-catalog.md), [directory](../features/user-directory.md), [deletion](../features/account-deletion.md) | `internal/access`, `cmd/access-catalog`, `Auth/account` |
| Настройки | [Auth policy](../features/auth-settings.md), [SMTP](../features/smtp-settings.md), [providers](../features/provider-settings.md), [retention](../features/retention-settings.md) | `Auth/settings`, `internal/app/auth`, `internal/config` |
| JWT: ключи, exchange, проверка | [план](../planning/jwt-access.md), [ADR004](../adr/004-jwt-access-profiles.md), [keys](../features/jwt-keys.md), [exchange](../features/jwt-exchange.md), [introspection](../features/jwt-introspection.md), [consumer](../features/jwt-consumer.md), [settings](../features/jwt-profile-settings.md) | `Auth/token`, `pkg/authjwt`, `internal/app/auth/token*` |
| Native: выдача, MFA, email OTP | [HTTP](../features/native-http.md), [refresh](../features/refresh-storage.md), [issuance](../features/native-issuance.md), [MFA](../features/native-mfa.md), [email OTP](../features/native-email-otp.md) | `Auth/token`, `Auth/mfa`, `Auth/methods/{password,emailotp}` |

## Проверки и эксплуатация

| Задача | Первичный документ | Код / evidence |
| --- | --- | --- |
| Текущий scope и выполнение | [implementation](../planning/implementation.md), [roadmap](../planning/roadmap.md) | [history](../planning/history.md): искать нужный заголовок, не читать весь архив |
| Security и восстановление | [угрозы](../threat-model.md), [JWT security matrix](../operations/jwt-security-acceptance.md), [restore gates](../operations/jwt-recovery.md) | `deploy/restore-auth-state.sql`, `scripts/postgres-restore.sh`, фичевые SQL/security tests |
| Приёмка и производительность | [сводка и открытые gates](../operations/acceptance-summary.md), [performance](../operations/performance.md), [baseline](../operations/load-baseline.md), [load/rest](../operations/load-rest.md) | `deploy/sandbox`, `Auth/account` retention/delivery, shared hasher/limits |
| Команды и стенд | [режим проверок](../planning/implementation.md#режим-проверок-после-уточнения-пользователя), [sandbox](../operations/local-sandbox.md) | `Taskfile.yml`, `.github/workflows/ci.yml`, `deploy/compose.sandbox*.yml` |

Шаблоны путей — ориентир поиска, не обещание отдельного пакета. Подробности фичи и тесты искать через её документ/Serena, а не расширять эту карту до списка файлов.
