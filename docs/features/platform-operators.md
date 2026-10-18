# Оператор платформы — основа MP2.3–MP2.4

18 октября 2026. Реализованы SQL realm, первый владелец, проверка прав, [opt-in операторский Auth profile](platform-login.md) и [read API каталога](platform-projects-api.md). Management mutations и cross-project bridge **не подключены**. По умолчанию runtime остаётся standalone; [ADR005](../adr/005-independent-projects.md), [план](../planning/multi-project.md).

## Граница полномочий

Платформенная БД использует существующую schema `auth` для операторов и `platform` для каталога и полномочий. В каждой проектной БД будет независимая `auth`; общих пользователей/SSO нет.

`internal/platform/operator/domain` задаёт realm ID, principal и шесть точных permissions:

| Permission | Назначение |
| --- | --- |
| `platform.projects.read` | Список и карточка проекта |
| `platform.projects.manage` | Создание и изменение состояния проекта |
| `platform.project_users.manage` | Пользователи целевого проекта |
| `platform.project_access.manage` | Роли и назначения целевого проекта |
| `platform.project_settings.manage` | Настройки целевого проекта |
| `platform.operators.manage` | Операторы платформы |

Подключены только GET list/detail проектов; остальные endpoints этой таблицей не объявляются готовыми. Права хранятся в `platform.operator_permissions`, не в проектном `auth.role_permissions`. Даже super-admin с одноимённой Auth permission не получает платформенного доступа. Сейчас все шесть прав получает только первый владелец; API делегирования отсутствует.

Repository принимает caller-owned pool и ожидаемый realm UUID из доверенной конфигурации установки, не из HTTP. UUID создаётся migration; operator profile сверяет marker и runtime grants до открытия маршрутов. [Redis/crypto scope](realm-isolation.md), exact HTTPS Host/Origin и host-only cookies подключены в opt-in profile и проверены локально; provisioning независимых project keys/fleet/реальный ingress ещё не реализованы.

## Первый владелец

Порядок в **новой платформенной БД**: Auth `migrations/000001_init.up.sql` → `platform/000001_catalog.up.sql` → `platform/000002_operators.up.sql`. Последняя отвергает используемый Auth realm: существующих пользователей, начатый setup или системный super-admin. Автоматического повышения администратора существующего проекта нет. Текущие migration-команды не переключены на этот набор.

Существующий `account/service.SetupService` получает операторский repository. Сохраняются bootstrap secret, limiter contract, Argon2id, подтверждение почты, TOTP, шифрование pending payload и десять recovery-кодов. Второй стек аутентификации не добавлен.

Завершение — одна Read Committed транзакция: access lock → realm row lock → Auth setup singleton → Auth administrator/TOTP/recovery → платформенные permissions/audit → initialized marker. Ошибка платформенной записи откатывает также Auth пользователя. Неверное доказательство фиксирует расход попытки; сроки и максимум сохраняет прежний setup. Сессия не выдаётся. Повторное/конкурентное завершение допускает одного владельца.

Общий `CompleteSetupInTransaction` — прежняя Auth операция с внешним владельцем транзакции; обычный проектный `CompleteSetup` также пользуется ей. Это не система произвольных hooks.

## Проверка доступа

Runtime split: `app/auth/app.go` открывает общие dependencies/hasher и выбирает одну assembly — прежнюю `realm.go` либо opt-in `operator.go`. `run.go` управляет background lifecycle. Operator profile использует matching platform scope и restricted pool, не создаёт второй Auth стек/JWT clients и не подменяет пользователя проекта. Несколько проектов/fleet registry/dispatcher ещё впереди; полный New на каждый проект не запускать.

`AuthorizeRead` делает один ограниченный SQL-запрос без положительного кеша. Требует ожидаемый initialized realm, platform permission, активного неудалённого пользователя, актуальный auth_version, живую browser/password session с действующими role revision bindings, password/MFA proofs не из будущего и существующие password/TOTP credentials. Driver details не возвращаются, отмена сохраняется в безопасной ошибке.

Это **snapshot чтения**, не разрешение следующей мутации. Изменения проектов/bridge требуют locks до commit, свежие proofs, audit/receipt и concurrency/revoke/lost-reply проверки. Маршруты управления состоянием/создания проектов и bridge ещё не открыты. Login/MFA и [platform recovery](platform-recovery.md) используют существующий Auth стек. Reset пароля не выдаёт grants, не повторяет bootstrap и не обходит MFA.

## Проверки

`task check` PASS, lint0. Реальный `TestPlatformOperatorsPostgres` PASS0.26s на PostgreSQL18.6/Linux arm64: SetupService с Argon2id/email/TOTP, учёт неверного кода, audit rollback, конкурентный first-owner, отсутствие сессии после setup, grants/marker/recovery rows. SQL authority проверена при revoke/expiry/block/auth_version/proof/role revision/permission changes, чужом realm, одноимённом Auth permission, PUBLIC ACL и cancellation. Session authority fixture вставляется SQL — это **не HTTP login**.

Catalog regression/up/down также PASS. Fixture удалена, рабочая Auth не менялась; [evidence](../planning/history.md#результат-mp23mp24-foundation--18-октября-2026).

Дополнительный [operator profile](platform-login.md) прошёл local restricted SQL/Redis/TLS setup/login/password recovery/revoke и targeted unit race; [scoped emergency/lost-factor tooling](platform-recovery.md) — отдельный SQL/HTTP/CLI drill. NOT RUN: реальный browser/SMTP/ingress/независимая проверка личности, two-runtime isolation, fleet/load/GC и cross-project bridge. MP2 целиком не закрыт.
