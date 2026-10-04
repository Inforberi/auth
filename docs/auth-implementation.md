# Пошаговая реализация Auth

Этот файл раскрывает [основной план](auth-plan.md) до конкретных изменений. Перенос инфраструктуры выполнен в рабочих файлах Auth; provenance и выбранные/отклонённые компоненты — [template-adoption](template-adoption.md). REF ниже обозначает только исторические пути go-template на зафиксированном commit, не локальную папку и не будущую зависимость. Пути назначения относительно корня Auth.

## Как выполнять

На текущей ветке сохранять пользовательские изменения. Один подэтап — один reviewable diff: изменить код/tests/config/docs, выполнить проверки, записать результат в таблицу основного плана. Не публиковать новый flow до готовности его security prerequisites. Независимые задачи можно выполнять параллельно, зависимые — после завершения prerequisites.

Обычная проверка изменений Go: `task check` (tests + lint). Дополнительные race/integration/security/container/API checks — только по затронутому риску и перед release; весь набор не повторять после каждой мелкой правки. Если обязательная для конкретного изменения проверка недоступна или падает, записать результат и не заявлять её прохождение. Задачи ниже не разрешают prod deploy/restore ради проверки.

Основной порядок: 1.1–1.8 → 4 → 5/6 → 7/8 → 9/10 → 11/12 → 14. Детализация разделов 2–3 и перенос 4.2–4.3 выполняются внутри первого этапа. Этап 0 до зависимых решений; 13.1 после 6 до любых production admin endpoints. Docs и security audit ведутся на каждом шаге.

## 1. Адаптация go-template и удаление reference — первый этап

- [x] 1.1. Восстановить сборку по инструкции ниже.
- [x] 1.2. Выполнить инфраструктурные задачи раздела 2.
- [x] 1.3. Выполнить окружение/toolchain/CI/dependency задачи раздела 3.
- [x] 1.4. Выполнить перенос HTTP validation и Swagger policy по 4.2–4.3; schema/domain задачи 4.1/4.4 оставить следующему этапу.
- [x] 1.5. Оценить REF `pkg/client.go/client_test.go`: либо адаптировать в `internal/core/infra/httpclient/` с bounds/redaction/TLS/redirect/SSRF/cancellation tests, либо отклонить wrapper в пользу стандартного transport/SDK. Записать решение сейчас; этапы 8/12 не зависят от source snapshot.
- [x] 1.6. Адаптировать REF backup/restore и Task/Compose tasks в рабочие `deploy/scripts/`/`Taskfile.yml`; проверить locks, exact targets, текущих writers, DB roles, failures и restore на disposable DB. Для logs/deploy выбрать полезные компоненты либо отклонить с причиной. Auto-deploy не включать. Финальная проверка с будущими billing/email workers остаётся этапом 14.
- [x] 1.7. Создать `docs/template-adoption.md`: source commit `4acce0b1b822742327a84c5216e7f1c899f08424`, все компоненты, решение/рабочие файлы, проверки и ограничения. Перенести полезные REF README инструкции в Auth docs; заменить ссылки на snapshot рабочими путями/документами.
- [x] 1.8. Временный `docs/reference/go-template/` удалён по явному запросу пользователя после переноса выбранных компонентов. Provenance и решения сохранены в `docs/template-adoption.md`; исходный соседний проект не затронут. Tests/lint и production drill выполнены ранее. Незавершённый dev smoke после CGO fix остаётся отдельным проверочным долгом, не поводом хранить source snapshot.

Готово: reference отсутствует, Auth содержит все выбранные и проверенные улучшения, дальнейшие задачи не требуют исходников другого проекта. Незавершённые проверки учитываются отдельно; удаление source snapshot не означает их прохождение.

## 0. Архитектура

- [ ] 0.1. Создать `docs/architecture.md` и ADR в `docs/adr/`: single-app independent deployment, модульные границы identity/session/access/entitlement/billing, ownership UUID/app scope и PostgreSQL/Redis sources of truth. Доставленный reference считать завершённым сбором материалов, а не завершением ADR.
- [ ] 0.2. Создать `docs/threat-model.md` по takeover/replay/linking/CSRF/privilege escalation/resource exhaustion/payment forgery; связать mitigation и negative tests с номерами подэтапов.
- [ ] 0.3. ADR по durable session revocation и challenges: failure semantics, transactional updates, outbox/inbox, Redis fallback, authentication context. Решение необходимо до 5.2/5.4/6.2–6.3.
- [ ] 0.4. Записать billing scope: личный account first, versioned catalog, один hosted checkout adapter. Перед 12.1 выбрать реальный provider по требованиям продавца. Common SSO/organizations/Mini Apps — включаемые расширения, не prerequisites базового шаблона.

Проверка: нет противоречий между schema/API/security/release scope; каждое нерешённое внешнее условие привязано к конкретному dependent шагу.

## 1.1. Детализация восстановления сборки

- [x] 1.1a. В `internal/featers/password_auth/service/forgot_password.go` завершить renderer → subject/body → `Send` и error handling. Использовать текущие `internal/core/infra/mailer/templates/reset_password.go/.html`; сохранить пользовательский HTML. Не публиковать reset endpoint раньше 5.2.
- [x] 1.1b. Проверить успешный render, escaping/URL generation и ошибку доставки содержательными tests в mailer/templates и password service. Не скрывать техническую ошибку пустой заглушкой.
- [x] 1.1c. Выполнить базовые checks. Зафиксировать remaining failures отдельно; не смешивать dependency/container updates с исправлением Send.

Готово: текущий модуль собирается; reset scaffolding корректно вызывает существующий mailer и проверяет его ошибки.

## 2. Адаптированная инфраструктура Auth

Все задачи этого раздела выполняются внутри 1.2; номера сохранены для точных ссылок и учёта выполнения.

| Шаг | Источник REF | Рабочие файлы Auth | Реализация и проверка |
| --- | --- | --- | --- |
| 2.1 | `internal/infra/config/config.go`, `config_test.go` | `internal/core/config/*`, infra config types | `Validate`, отдельный env key absolute TTL, durations/pools/secrets/URL policy; table tests invalid/missing/prod configuration |
| 2.2a | `internal/transport/http/server/server.go`, `cmd/api/main.go`, `internal/app/app.go` | `internal/core/infra/httpserver/server.go`, `internal/app/auth.go`, `cmd/auth/main.go` | Independent bounded shutdown, signal/resource cleanup; тест завершения активного HTTP request и cancellation |
| 2.2b | `internal/infra/postgres/postgres.go` | `internal/core/infra/postgres/postrges_pool.go` | Connect/Ping deadline, Close при failed Ping, сохранить pool options; failure/timeout проверка |
| 2.3 | `internal/infra/logger/*`, `middleware/request.go` | `internal/core/infra/logger/*`, HTTP middleware/router | Context logger + Request ID, route-based redaction/proxy policy; negative tests token/query/header leaks |
| 2.4 | `router/router.go`, `router_test.go` | HTTP health handler/router и `internal/app/auth.go` | Live + bounded ready PostgreSQL/Redis; healthy/failure/timeout HTTP tests, никаких DSN в ответах |
| 2.5 | Durable audit в template отсутствует | `internal/core/audit/audit.go`, policy в template-adoption | В 1.2 создан port без sink/enforcement; durable storage и transactional writes по ADR этапа 0 и lifecycle этапов 4–6. Access log не полноценный audit |

Для каждого шага обновить env/config reference и статус. Health и Swagger не заменяют auth checks. Не копировать template error wrapping так, чтобы потерять тип ошибки или раскрыть DSN.

## 3. Toolchain, окружение, CI и dependencies

Все задачи этого раздела выполняются внутри 1.3; отдельный повторный перенос после завершения этапа 1 не требуется.

- [x] 3.1. Сверить Auth `go.mod`, CI/builder/linter compatibility и официальные releases. Согласовать одну Go version; восстановить lint/race. REF `go.mod/go.sum` — inventory, не target lockfile. Исправить чужой `gci` prefix в `.golangci.yml`.
- [x] 3.2. Из REF `deploy/Dockerfile.dev/.prod`, `.dockerignore`, `.air.toml` создать Auth dev/prod Dockerfiles и dev profile; Air/hot reload отклонены по решению template-adoption. Сборка `./cmd/auth`, корректное имя binary, target architecture, nonroot runtime. Исключить secrets/data и `docs/reference/` из Docker context. Проверить actual image build, signal handling и runtime smoke.
- [x] 3.3. Из REF `deploy/compose.dev.yml` и `.env.example` собрать `deploy/compose.dev.yml` Auth: PostgreSQL/Redis, local SMTP test service по выбранному решению, migration ordering, consistent passwords/healthcheck, localhost bindings. Обновить задачи dev/migrate/db в `Taskfile.yml`; не трогать существующие данные. Проверить config и startup на изолированном Compose project.
- [x] 3.4. Из REF `deploy/compose.prod.yml`, `.env.prod.example` создать Auth prod profile: DB/Redis без публичных ports, secret provisioning, minimal privileges, readonly/caps/health/TLS assumptions. Продумать миграционный DB role отдельно от runtime. Проверить rendered config без печати secrets, build/smoke; не выполнять deployment.
- [x] 3.5. Все команды перенесены в корневой `Taskfile.yml`, makefile и `mk/` удалены. `task check` выполняет tests + lint без загрузки настоящей `.env`; race/security/integration/Swagger/Compose остаются отдельными задачами. CI устанавливает Task 3.53.1 и запускает сокращённый набор. Auto-deploy выключен. Загрузка Taskfile и dry-run проверены; GitHub CI не запускался.
- [x] 3.6. Отдельные dependency updates: HTTP/Swagger → PostgreSQL/Redis → crypto/прочие. Сначала installed version + current docs через Context7, затем compatibility/changelog и адаптация кода. Проверить module graph/tidy, tests, docs, container build и vulnerability findings. Для crypto проверены старые hashes и parser bounds; новая rehash policy остаётся 6.7. Не перезаписывать Auth `go.sum` снимком.

Готово: checks воспроизводимы локально/CI, isolated dev startup проходит, prod image/config проверены; external deployment не является частью этого этапа.

## 4. Схема и API

Перенос источников в 4.2–4.3 выполняется в 1.4. На этапе 4 остаются schema/domain изменения и проверка API на обновлённой схеме; повторное чтение reference не нужно.

- [ ] 4.1. Проверить/адаптировать существующие `migrations/000001_init.up.sql/.down.sql`, domain models и PostgreSQL repos: UUID, status/deletion, contacts/credentials, timestamps, UNIQUE/FK/CHECK/indexes. Up/down/up только на disposable DB; pre-production правило редактирования текущей миграции сохраняется.
- [x] 4.2. Из REF `httpx/request.go`, `json.go`, `request_test.go` адаптировать текущий `internal/core/transport/http/httpx`: content type/body bounds, single value, unknown fields, DTO validation. Сохранить Auth error envelope и документировать изменения statuses. Negative tests malformed/oversized/trailing JSON; не применить decoder к подписываемому webhook до raw-body verification.
- [x] 4.3. Из REF router/Swagger jobs перенести policy и pinned generation в `Taskfile.yml`/Auth router. Убрать наследие finance metadata из `cmd/auth/main.go` и generated `docs/*`. UI off in prod; dev mail endpoint unavailable in prod. Swagger 2.0 остаётся текущим контрактом до отдельного решения о OpenAPI 3.
- [ ] 4.4. Добавить schema/API contract checks, generation drift и реальное совпадение routes/status/DTO/security. Snapshot Swagger — пример структуры, не API Auth.

## 5. Email/password lifecycle

- [ ] 5.1. Schema + use cases + repo + HTTP для verify/resend; unverified policy и generic public responses, delivery retry/outbox по ADR. Проверить expiry/replay/resend/rate limits.
- [ ] 5.2. Завершить forgot/reset challenge storage/consumption и password update с durable invalidation. URL из trusted config; not-found отличать от DB failure внутренне. Проверить конкурирующий reset, expired/replayed token и SQL/Redis/email failures.
- [ ] 5.3. Session HTTP API: logout/logout-all/me/list/revoke-own и cookie cleanup. Проверить ownership/CSRF, current session и очистку индексов.
- [ ] 5.4. Enforce blocked/deleted users/auth version в session validation и login. Проверить existing sessions и racing requests; поведение зависимостей fail-closed по ADR.
- [ ] 5.5. Confirmed email change с fresh auth, уведомлением старого адреса и unique ownership; проверить чужой email/link race.
- [ ] 5.6. Account deletion/retention: revoke methods/sessions, согласовать subscription cancellation и сохранение платёжной истории; запретить takeover через переиспользование связанной identity.

Рабочие места: `internal/featers/password_auth/*`, session module, core domains/mailer, SQL и router. Схема/DTO/docs/tests обновляются в каждом подэтапе. Email delivery проверяется в staging отдельно от mocks.

## 6. Session и authentication security

- [ ] 6.1. `ValidateSession`, cookie helpers и middleware: expiry на равенстве, clamp absolute deadline, cookie refresh, rotation/fresh auth. Table tests boundaries и реальный browser smoke.
- [ ] 6.2. Redis repo refresh/delete/indexes: атомарное обновление только актуальной сессии, согласованные create/logout-all и revoke. Integration race tests с настоящим Redis; revoked session не возрождается.
- [ ] 6.3. По ADR внедрить durable auth version/invalidation при password reset/change/block. Проверить PostgreSQL/Redis partial failures и concurrent session issuance; outbox alone не заменяет enforcement актуальности.
- [ ] 6.4. Distributed limits по IP/account/challenge, parser bounds и hashing concurrency. Fuzz corrupted hashes, load/resource checks, rate-limit bypass/proxy/failure tests.
- [ ] 6.5. CSRF/Origin/CORS/security headers, local HTTPS для `__Host-session`, SMTP TLS/deadlines и secret redaction. Проверить login/linking/изменяющие запросы и email/OIDC browser compatibility.
- [ ] 6.6. Register UNIQUE race, registration-success/session-failure и retry contract. Содержательные transaction tests, стабильные domain errors.
- [ ] 6.7. Password policy + compromised passwords + safe rehash. Не менять существующие пароли молча; проверить старые корректные hashes, malformed data и migration path.
- [ ] После 6 выполнить **13.1 MFA** до административных production APIs. Этот шаг не откладывается до завершения billing.

## 7. Модель identities

- [ ] 7.1. Schema/domain/repo identities: стабильный user UUID, verified issuer/subject, provider/client scope при необходимости, email optional; уникальность и concurrent resolution.
- [ ] 7.2. Общий orchestration identity resolution → account policy → session, typed adapters без искусственного одинакового API для email и OIDC. Сохранить совместимость существующих users/credentials.
- [ ] 7.3. SSO только при включённом профиле: ADR и staging prototype на двух apps, готовый IdP/поддерживаемая protocol implementation, audience/clients/logout/hash transition. Независимый шаблон не блокируется этим extension.

Template не содержит identities/SSO/RBAC: эти задачи реализуются из требований Auth и официальных protocol docs, не из готового кода REF.

## 8. Telegram/OIDC/passwordless

- [ ] 8.1. Общий OIDC client flow: trusted discovery/redirects, state browser binding, PKCE S256, nonce где поддерживается, JWT signature/issuer/audience/expiry и single-use callback. SDK выбрать перед реализацией по текущей документации.
- [ ] 8.2. Дополнительные providers подключать конфигурацией/адаптерами после первого; OAuth-only identity получать по официальному API, не считать arbitrary email доказательством.
- [ ] 8.3. Telegram web OIDC adapter поверх 8.1, без обязательного email/UserInfo, minimal scopes; callback verification + actual staging login.
- [ ] 8.4. Email OTP: keyed verifier, попытки/TTL/rate limit, одноразовое потребление, delivery. Проверить resend/replay/parallel consume и отсутствие enumeration.
- [ ] 8.5. Optional Mini Apps: verified `initData`, auth_date/window/replay и явное сопоставление OIDC/Mini Apps identity. `initDataUnsafe` не доверять.
- [ ] Использовать рабочий transport, выбранный и проверенный в 1.5, либо официальный SDK; проверить provider-specific timeout/redirect/retry/redaction policy. Исходный REF для реализации новых интеграций не требуется.

Каждый adapter имеет config validation, safe disabled mode, contract/negative tests и staging check; secrets и callback tokens не публикуются.

## 9. Provider policy и linking

- [ ] 9.1. Config policy + public method discovery; enforce enabled/registration/app policy на start/callback/verify. Настройки до admin protection задаются file/env.
- [ ] 9.2. Link/unlink с fresh auth и binding к user/session/intent; ownership verification и UNIQUE race handling; запрет auto-merge по email и удаления последнего способа.
- [ ] 9.3. Preferences/default login и собственные устройства; выбор метода не меняет rights, изменение session/user во время linking отменяет flow.
- [ ] 9.4. Protected nonsecret admin settings API только после 10 + 13.1; audit/fresh auth и сохранение последнего административного доступа.

## 10. Roles/permissions

- [ ] 10.1. Single-app scope и schema/domain для roles/permission grants, deny-by-default; настройки расширяемы продуктом.
- [ ] 10.2. Центральный authorization service/middleware и resource ownership для read/list/write/admin APIs. DTO не позволяет self-promotion и подмену user/app scope.
- [ ] 10.3. Одноразовый operational bootstrap admin и safe role changes/revoke; MFA + fresh auth + durable audit. Проверить last admin recovery и privilege escalation.
- [ ] 10.4. Multi-app memberships/platform_admin/organizations — только расширенный профиль с отдельными cross-app tests.

Готово: member/admin и custom permission проверены backend; тарифы не участвуют в выдаче административных прав. UI следует API contract.

## 11. Entitlements/quotas без provider

- [ ] 11.1. Product/plan/feature keys + versioned catalog, grant owner/scope/source/period; Free/Pro как example config. SQL constraints исключают неоднозначного владельца.
- [ ] 11.2. Manual/trial grants с audit/expiry; backend feature checks, no Pro→admin и no admin→paid bypass.
- [ ] 11.3. Atomic usage/quotas, billing period/reset policy, bounded cache/invalidation. Integration tests concurrency/expiry/downgrade; сохранение данных при снижении лимита.

## 12. Payments

Подробные варианты и критерии находятся в этапе 12 [основного плана](auth-plan.md). Здесь порядок рабочих изменений:

- [ ] 12.1. После выбора provider: schema/domain/repo billing accounts/orders/payment attempts/subscriptions/refunds/event inbox/outbox, amount/currency/price snapshot и state machine. Не создавать все будущие таблицы до определения сценариев.
- [ ] 12.2. Hosted checkout adapter и protected purchase API: backend owner/price/amount, allowed return URLs, provider idempotency + local recovery. Contract tests timeout-after-provider-success и repeat request.
- [ ] 12.3. Provider webhook transport: raw-body/signature или официальная authenticated verification; durable event inbox перед ACK, event/payment uniqueness; worker retries/backoff/error queue.
- [ ] 12.4. Payment state transitions → entitlement delivery: success/pending/failure, renewal/cancel/expiry/grace. Duplicate/unordered/concurrent events не продлевают доступ дважды.
- [ ] 12.5. Refund/dispute и reconciliation job; lost events, provider/local mismatch, audit/alerts. Cancellation повторяется до подтверждения provider, а не только локально.
- [ ] 12.6. Optional Telegram Stars: authenticated Bot API updates, pre-checkout ownership/amount/XTR, `successful_payment`, charge/update dedup, refund и paysupport; отдельно от web checkout.
- [ ] 12.7. End-to-end sandbox lifecycle и documented adapter capabilities. Второй adapter подключать по interface/contract tests; не объявлять не протестированный provider поддержанным.

Рабочие места: новый billing module по ADR, entitlement service, provider config/HTTP transports, schema и API docs. В REF нет payments: source для implementation — выбранный официальный API/SDK и требования плана.

## 13. MFA и кабинет

- [ ] 13.1. После 6 добавить MFA/TOTP/recovery codes, защищённые secrets at rest, verified enrollment, single-use recovery/TOTP, session authentication context и fresh-auth step-up. Reset/lost-factor policy без обхода MFA. Проверить enrollment/replay/brute-force/session state и backend admin enforcement.
- [ ] 13.2. User/admin API для профиля/methods/sessions/MFA/plans/history/subscription/settings. UI — отдельный выбранный release scope; не блокировать backend переносимость конкретным frontend framework.
- [ ] 13.3. Passkeys/enterprise methods — отдельные extensions с собственным origin/RP ID/protocol/staging acceptance.

## 14. Operations и перенос в другой проект

- [ ] 14.1. Дополнить audit/metrics/alerts, health dashboards и runbooks: dependency failures, compromise/revoke, secret rotation, delayed email/webhook, billing mismatch. Не использовать PII/token в metric labels.
- [ ] 14.2a. Развить уже перенесённые в 1.6 Auth scripts/tasks под итоговые schema/paths/services/writers/migration+runtime roles. Добавить остановку новых email/billing workers, safe target guards и healthcheck итоговых access/billing инвариантов; source snapshot не требуется.
- [ ] 14.2b. Review restore failures на каждом шаге и Linux tooling; disposable DB drill, schema/access/billing healthcheck, session invalidation и payment reconciliation после restore. Off-site encrypted backup/RPO/RTO; существующую production/local DB не пересоздавать ради проверки.
- [ ] 14.3. Завершить созданные в 1.7 Auth quick start/config/operations/copy guide, `SECURITY.md`, extension и dependency upgrade guides. Exact commands должны проходить на чистом checkout; provenance остаётся в `docs/template-adoption.md`.
- [ ] 14.4. Отдельный mechanical rename legacy module/imports/names с tests. Перенести шаблон в disposable sample product: новый module/name/secrets, custom role/permission и plan/feature, изменённые письма; проверить запуск без соседних проектов.
- [ ] 14.5. Dependency update workflow/upstream fixes/changelog и release tag после checklist. Optional operational компоненты, выбранные в 1.6, проходят собственные финальные checks; автоматическое deployment не включать при обычном переносе.

Готово: production checklist основного плана выполнен, sample project доказывает reuse, поддерживаемые профили перечислены в release notes. Reference удалён ещё в 1.8; происхождение решений сохранено краткой документацией.

## Учёт выполнения

Текущий результат: tests/lint и production drill прошли. Dev smoke после CGO fix не повторялся (пользователь отклонил запуск), reference удалён по явному запросу пользователя; dev smoke остаётся непроверенным. Не считать dev startup проверенным; новые проверки без отдельного запроса не запускать.

При завершении подэтапа добавить в основной план: номер, изменённые файлы/commit при наличии, команды и результаты checks, schema/API change, ограничения и следующий шаг. Статусы «материалы собраны», «адаптировано» и «проверено в staging» различаются. Этап 1.1–1.7 адаптирован; cleanup 1.8 выполнен; dev smoke после CGO fix пока не подтверждён. Новые auth flows не реализовывались.

## Режим проверок после уточнения пользователя

Обычный шаг: `task check` — tests + lint. Не повторять полный набор после каждой мелкой правки. Race/security/Swagger/Compose/container/integration запускать отдельно только для затронутого риска или release gate; vet/build/format не дублировать отдельными checks поверх tests/lint. CI — tests/lint, security и image build; integration/race не запускаются автоматически на каждый push. В `deploy/scripts` оставлены только backup core, host restore wrapper и один integration runner; Swagger проверяется Task recipe без отдельного shell-файла.
