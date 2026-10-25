# Карта проекта

Начать с [текущего шага](current-task.md), затем выбрать нужную строку ниже. Это навигация, не список обязательного чтения: статусы — в плане, поведение — в коде, доказательства — в history. Правила — [AGENTS.md](../../AGENTS.md).

Пути к исходникам относительно корня репозитория; Auth = `internal/auth`, Project = `internal/platform/project`.

## Проекты и сборка

| Задача | Первичный документ | Код |
| --- | --- | --- |
| План независимых проектов | [MP1–MP8](../planning/multi-project.md), [ADR005](../adr/005-independent-projects.md) | `Project`, `internal/platform/operator` |
| Каталог, создание, состояния | [каталог](../features/project-catalog.md), [read API](../features/platform-projects-api.md), [создание](../features/platform-project-creation.md), [изменения](../features/platform-project-mutations.md), [lifecycle](../features/project-lifecycle.md) | `Project/{domain,service,repository/postgres,transport/http}` |
| Подготовка БД и ключей | [reservation](../features/project-preparation.md), [storage](../features/project-storage-preparation.md), [schema](../features/project-schema-preparation.md), [credentials](../features/project-secrets-preparation.md) | `cmd/project-prepare`, `Project/{storage/postgres,credentials,repository/postgres}`, `deploy/*grants.sql` |
| Подготовка проекта | [закрытый managed профиль](../features/project-managed-readiness.md), [настройки, SMTP, runtime, admission, activation/recovery и закрытый setup-профиль](../features/project-onboarding-preparation.md), [standalone первый администратор](../features/initial-setup.md), [владелец платформы](../features/platform-operators.md#граница-полномочий) | `cmd/project-prepare/{main,command}.go`, `internal/app/auth/project_onboarding*`, `Project/{credentials/onboarding*,repository/postgres/{onboarding*,managed_runtime},storage/postgres/onboarding*}`, `Auth/account/*/setup*`, `internal/transport/http/router/project_onboarding*` |
| Оператор платформы | [foundation](../features/platform-operators.md), [login](../features/platform-login.md), [recovery](../features/platform-recovery.md) | `internal/platform/operator`, `internal/app/auth/operator*`, `router/operator.go`, `cmd/admin-recovery` |
| Управление ролями из платформы | [intent/admission/receipt](../features/platform-role-intents.md), [opt-in HTTP create/read/reconcile](../features/platform-roles-api.md), [grant/revoke и сессии](../features/platform-role-assignments.md), [каталог ролей](../features/platform-role-directory.md) | `Project/domain/{role_creation,platform_actor,directory}.go`, `Project/repository/postgres/{role_*,directory}.go`, `internal/access/repository/postgres`, `migrations` |
| Auth policy проекта из платформы | [контракт API и readiness](../features/platform-auth-settings.md) | `Project/{service,repository/postgres}/auth_policy.go`, `Project/repository/postgres/policy_*`, `Project/transport/http/*auth_policy*`, `Auth/settings` |
| Пользователи из общей панели | [список и карточка с назначениями](../features/platform-user-directory.md) | `Project/{service,repository/postgres}/user_directory.go`, `Project/transport/http/{list_project_users,read_project_user,users}.go`, `Auth/account/{service,repository/postgres,transport/http}/*user*` |
| Результаты административных операций | [read-own и receipt reconciliation](../features/platform-role-outcomes.md) | `Project/repository/postgres/role_{outcome_read,reconcile,outcome,execution}.go` |
| Authority/transport приёмка platform roles | [матрица и текущий verification gate](../operations/platform-role-faults.md) | `cmd/project-prepare/role_{authority,transport,wire}_integration_test.go` |
| Профиль проектного SQL runtime | [identity/version/checksum/grants](../features/project-runtime-profile.md) | `Project/repository/postgres/{runtime_profile,onboarding_runtime}.go`, `Project/storage/postgres/schema_identity.go`, `migrations/project_identity.go`, `deploy/runtime*` |
| Подключения к готовым проектам | [trusted targets, credential reader, bounded registry/leases](../features/project-runtime-registry.md) | `Project/runtime`, `Project/repository/postgres/{runtime_credentials,runtime_connection,project_transaction}.go`, `deploy/platform-runtime-reader-grants.sql` |
| Проектный password/session runtime | [первый Login и lifetime пула](../features/project-password-runtime.md), [регистрация](../features/project-registration-runtime.md), [MFA challenge/enrollment](../features/project-mfa-runtime.md), [SMTP runtime](../features/project-smtp-runtime.md), [проектные email и delivery](../features/project-email-runtime.md), [invitations/temporary/binding/change](../features/project-account-runtime.md), [включение delivery/lifecycle](../features/project-delivery-lifecycle.md) | `internal/app/auth/project_password*`, `Project/runtime/pool.go`, existing password/session/settings services |
| Входы проектной Auth-сборки | [read-only key/policy loader](../features/project-auth-loader.md) | `Project/credentials/auth.go`, `Project/repository/postgres/{auth_configuration,runtime_credentials}.go` |
| Сборка и lifecycle проектных пулов | [operational config, commit observer, shutdown](../features/project-runtime-lifecycle.md) | `internal/app/auth/project_runtime.go`, `internal/config/project_runtime.go`, `Project/runtime/lifecycle_observer.go`, `Project/service/change_state.go` |
| Межэкземплярная сверка пулов | [bounded resident polling](../features/project-runtime-sync.md) | `Project/runtime/sync.go`, `Project/repository/postgres/runtime_{binding,state,credentials}.go`, `cmd/project-prepare/runtime_sync_integration_test.go` |
| Ресурсы административных операций | [SQL deployment budget и HTTP/Redis admission](../features/platform-resource-bounds.md) | `internal/config/platform_resources.go`, `Project/admission`, `Project/transport/http/capacity.go`, `internal/infra/redislimit` |
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
| Настройки | [Auth policy](../features/auth-settings.md), [SMTP](../features/smtp-settings.md), [план шаблонов писем](../planning/email-templates.md), [providers](../features/provider-settings.md), [retention](../features/retention-settings.md) | `Auth/settings`, `internal/app/auth`, `internal/config` |
| JWT: ключи, exchange, проверка | [план](../planning/jwt-access.md), [ADR004](../adr/004-jwt-access-profiles.md), [keys](../features/jwt-keys.md), [exchange](../features/jwt-exchange.md), [introspection](../features/jwt-introspection.md), [consumer](../features/jwt-consumer.md), [settings](../features/jwt-profile-settings.md) | `Auth/token`, `pkg/authjwt`, `internal/app/auth/token*` |
| Native: выдача, MFA, email OTP | [HTTP](../features/native-http.md), [refresh](../features/refresh-storage.md), [issuance](../features/native-issuance.md), [MFA](../features/native-mfa.md), [email OTP](../features/native-email-otp.md) | `Auth/token`, `Auth/mfa`, `Auth/methods/{password,emailotp}` |

## Проверки и эксплуатация

| Задача | Первичный документ | Код / evidence |
| --- | --- | --- |
| Организация разработки и перенос правил | [AI workflow: исполнители, фоновые проверки, ошибки, выбор инструментов](development-workflow.md) | [AGENTS.md](../../AGENTS.md), существующие runner/CI |
| Текущий scope и выполнение | [implementation](../planning/implementation.md), [roadmap](../planning/roadmap.md) | [history](../planning/history.md): искать нужный заголовок, не читать весь архив |
| Security и восстановление | [угрозы](../threat-model.md), [JWT security matrix](../operations/jwt-security-acceptance.md), [restore gates](../operations/jwt-recovery.md) | `deploy/restore-auth-state.sql`, `scripts/postgres-restore.sh`, фичевые SQL/security tests |
| Приёмка и производительность | [сводка и открытые gates](../operations/acceptance-summary.md), [performance](../operations/performance.md), [baseline](../operations/load-baseline.md), [load/rest](../operations/load-rest.md) | `deploy/sandbox`, `Auth/account` retention/delivery, shared hasher/limits |
| Команды и стенд | [режим проверок](../planning/implementation.md#режим-проверок-после-уточнения-пользователя), [sandbox](../operations/local-sandbox.md) | `Taskfile.yml`, `.github/workflows/ci.yml`, `deploy/compose.sandbox*.yml` |

Шаблоны путей — ориентир поиска, не обещание отдельного пакета. Подробности фичи и тесты искать через её документ/Serena, а не расширять эту карту до списка файлов.
