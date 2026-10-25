# Проектные приглашения, временные пароли и управление email

MP4.1h,25 октября2026. Решение перед реализацией.

- Подключить existing invitation, temporary-password, email binding/change services к выбранному project key, scoped crypto/Redis, shared bounded hasher и current SQL/session/actor authority. Не копировать SQL, permissions или бизнес-сценарии.
- Config/features opt-in, immutable snapshot, URLs только из trusted HTTPS origin проекта. Не использовать request Host/platform ENV fallback. Disabled не создаёт дополнительные pools/workers или скрытые readiness capabilities.
- Операции выполняются под одной existing UsePool lease, services/repos создаются внутри callback и не сохраняются. Проверять current key до/после; final failure не раскрывает результат/secret stale проекта и не обещает rollback уже committed side effect. Во время hash/network не держать physical SQL connection.
- Сохранить explicit admin actor/session/MFA/fresh/delegation/idempotency guards; пользовательские завершения только по existing purpose token/setup authority. Ни implicit admin impersonation, ни выдачи project admin роли из public input.
- Письма только через existing encrypted account outbox. Общий bounded runner должен дать каждой подключённой очереди шанс независимо от HTTP traffic, без бесконечного per-project state или worker на каждый проект. Не менять SQL lease/retry/eligibility при расширении выбора очередей.
- Временный пароль передавать только по существующему контракту; если текущая реализация выдаёт его один раз API-ответом, не придумывать email-отправку или логирование.
- Не публиковать HTTP/readiness/UI; без новых deps/schema/реальных ENV/БД. Проверки — formatter/diff, затем Luna task check/affected race/actual SQL+Redis scenario/negative/scope/queue fairness на immutable snapshot.

## Внутренний API

- `ProjectEmail`: ProvisionUser/ReissueInvitation/ActivateInvitation, RequestEmailBinding/ConfirmEmailBinding, RequestEmailChange/ConfirmEmailChange/ReportEmailChange/RecoverEmailChange. Входы — existing service DTO/Principal/Proof, без caller-supplied role grants или альтернативных proof правил.
- `ProjectEmailConfig`: независимые VerificationEnabled/RecoveryEnabled, existing Invitations/Binding/Change config flags, FreshAuthTTL только для change. Включённые URL проверяются на общий trusted HTTPS Origin; binding-only не требует фиктивных verification/reset URLs. Caller должен явно выбрать consumers; это не замена сохраняемой SQL Auth policy или readiness.
- `ProjectPassword`: ProvisionTemporaryPassword/ReissueTemporaryPassword/BeginTemporaryPassword/CompleteTemporaryPassword с отдельным TemporaryPassword config. Begin возвращает только setup authority, не normal session. Выданный API secret не ставится в email outbox и остаётся JSON-hidden. SMTP/ProjectEmail не нужны этому компоненту.

Services/repositories создаются на borrowed pool внутри existing guarded operation. Общий ValidateFreshAuthTTL вынесен из session Config.Validate в функцию того же пакета и переиспользуется без изменения1m–15m границ. Feature-disabled методы отказывают до обращения к pool/services; successful token/secret/time возвращаются только после финального current guard. Actor должен аутентифицироваться как пользователь выбранного проекта; общего platform operator session нельзя передать как project-user proof. Operator bridge для этих операций — отдельная задача, impersonation не добавлен.

## Доставка и справедливость

Runner по-прежнему выполняет одну account и одну reset попытку на проект за проход. Account очередь ротируется раз в полный обход каталога: verification → change → invitation → binding. На каждом шаге selected queue получает приоритет, verification — fallback. Existing NewWithDelivery использует только один дополнительный флаг, claim/finish/crypto не менялись. Это устраняет reset локального repository счётчика при каждой ephemeral сборке и не хранит map с состоянием каждого проекта.

Курсор и turn ограничены памятью страницы/четырьмя состояниями, ошибочная выборка не продвигает очередь. После restart цикл начинается сначала, durable SQL lease/backoff/idempotency остаются authority. Это шанс каждой очереди за четыре завершённых обхода, не wall-clock SLA или распределённая fairness по fleet. Ранее созданные подходящие письма могут доставляться после отключения producer; flags delivery не включают HTTP или issuance.

## Проверки и ограничения

Добавлены unit tests disabled-before-dependencies, project URL/fresh-auth configuration, binding-only без password-reset URL и возможностей каждой очереди за полный цикл. Actual command SQL+Redis fixture добавляет synthetic manager с accounts.users.manage/accounts.email.bind и явными backend session/MFA proofs, external-only binding target, отдельный password/change account. Это тестовые proofs через root fixture; production authentication/MFA не обходятся.

Проверяются invitation idempotency/reissue/old-token rejection/activation/replay, denied actor, binding code/confirm/replay, change confirm→old-owner report→protected recovery/replay/current login contact/hash, temporary provision/replay secret masking/reissue/old secret rejection/setup/complete/normal Login. Отдельный owned SMTP endpoint не предлагает STARTTLS: runner каждой очереди делает safe reject/retry, не передаёт AUTH/body. После теста восстанавливаются policy/SMTP и удаляются собственные users/role/точные scoped Redis keys; parent reset-global не удаляется.

Formatter/diff main, task check/affected race/actual full TestPrepareCommandSQL — отдельная Luna на immutable snapshot. Luna V3: actual full TestPrepareCommandSQL exit0 без SKIP и targeted cmd lint exit0/0issues; V1 task check/lint0 и affected race PASS сохранены, V2/V3 исправляли только fixture SQL seed/cleanup. Manifest17 совпал до/после и с main; RedisDB15 пуста, owned fixtures удалены. Snapshot `/private/tmp/auth-project-account-v3.ey656x8o`; evidence — history. Не считать это external SMTP, HTTP/host routing, provider/JWT, MP5 isolation matrix, fleet/GC/capacity или UI приёмкой. Новых библиотек/schema/реальных ENV/БД нет.
