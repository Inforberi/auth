# План реализации универсального production Auth-шаблона

Обновлено 8 октября 2026. Рабочий проект: `/Users/inforberi/Desktop/Projects/auth`, ветка `feat/register-ai`. Исходный анализ: HEAD `5e8f5e5` и незакоммиченные изменения reset HTML/HTTP-ошибок. Источник инфраструктурных улучшений: `/Users/inforberi/Desktop/Projects/go-template`, main, изученный HEAD `4acce0b`.

## 1. Назначение и правила

Auth — переиспользуемый Go-шаблон, который можно скопировать или форкнуть, настроить и доработать под другой продукт. Общие механизмы идентификации, сессий, прав и подписок отделены от конкретного продукта. Обязательны email/password, passwordless email, Telegram, роли/permissions, тарифы и подключаемая оплата. Дополнительные OAuth/OIDC-провайдеры подключаются через адаптеры.

Основной сценарий — отдельный экземпляр Auth для каждого проекта, с собственной БД, secrets и пользователями. Общий аккаунт и SSO между независимыми проектами — отдельный профиль, который требует решения об IdP и прототипа; копирование шаблона само по себе не означает общий вход. Первый релиз работает с одним приложением; границы app scope проектируются так, чтобы позднее добавить несколько приложений без потери user UUID. Не вводить полноценную multi-tenancy, организации и свой OAuth server ради абстрактной универсальности.

Вход отвечает на вопрос «кто пользователь», permissions — «что ему разрешено», entitlements — «какие функции доступны по тарифу». Pro не даёт административные права; admin не получает Pro автоматически. Роли и подписки могут различаться по приложениям.

Работать непосредственно в указанном каталоге и ветке; не выполнять реализацию в прежнем worktree. Незакоммиченные изменения пользователя сохранять. Один рабочий заход — один этап или подэтап, отдельный проверяемый diff; не смешивать инфраструктуру, обновление зависимостей, новые login methods и billing в одно изменение.

**Миграции:** проект не в production. Для текущей разработки редактировать существующие up/down SQL-файлы напрямую, новые миграции не создавать. Итоговую схему проверять на чистой отдельной тестовой БД, включая up/down/up. Не сбрасывать существующую локальную БД и не удалять данные без явного разрешения. Переписывание SQL-файла не обновляет уже применённую схему автоматически. После первого production выпуска дальнейшие изменения выпускаются отдельными миграциями.

**Качество:** каждый завершённый этап выполняется с production требованиями: безопасная конфигурация, корректная обработка ошибок, актуальные API docs и содержательные проверки. Production-готовность всего сервиса подтверждается совокупностью критериев релиза, а не завершением одного этапа. Не проверенные интеграции и ограничения явно фиксируются.

По запросу пользователя реализован инфраструктурный перенос этапа 1; reference уже удалён, dev smoke проверяется отдельно. Остальные задачи ниже — будущая реализация, их наличие в плане не означает готовность кода. После каждого подэтапа обновлять статус, фактические проверки и ограничения в этом файле.

### Результат, к которому идём

- Безопасный жизненный цикл аккаунта: регистрация, подтверждение/смена email, вход, восстановление, смена пароля, привязка/отвязка методов, блокировка и удаление.
- Сессии с немедленным отзывом, управлением устройствами и защитой чувствительных действий; MFA для административного доступа.
- Независимые account/auth methods, session, access, entitlement, billing и infrastructure; внешние identities принадлежат account. Продуктовые функции, цены, роли и лимиты задаются настройками/расширениями проекта.
- Версионированный API, SQL-схема, проверяемые dev/prod окружения, наблюдаемость, backup/restore и воспроизводимый CI.
- Инструкция переноса в другой проект, пример адаптации и отдельный процесс безопасного обновления зависимостей.

Базовый auth-профиль не требует оплаты. Расширенный billing-профиль подключается отдельно. Полный набор шаблона включает email/password + verification/reset, email OTP, Telegram web login, account linking, member/admin с permissions, MFA администратора, Free/платные тарифы, разовую оплату и подписки через один выбранный web-провайдер. Telegram Mini Apps/Stars обязательны только для профиля запуска внутри Telegram; второй web-провайдер, общий SSO, passkeys и организации выпускаются отдельно. Каждый дополнительный профиль имеет свой набор проверок; выключенная или непроверенная интеграция не считается поддерживаемой.

## 2. Что уже есть и что отсутствует

Есть HTTP/Chi, конфигурация cleanenv, Zap, PostgreSQL/pgx и Redis, SMTP, Swagger 2.0, SQL users/profile/password_credentials. Реализованы регистрация и вход email/password, Argon2id, смена пароля, cookie-сессии с TTL/продлением, service logout methods, middleware и mock tests. HTTP server имеет timeouts.

В router подключены POST `/api/v1/auth/register/email`, `/api/v1/auth/login/email`, защищённый `/api/v1/auth/change-password`. Logout существует на уровне service, но не подключён HTTP-маршрутом. Reset начат, но не завершён.

Нет OAuth/OIDC/Telegram, email verification/OTP, provider registry/settings, account linking, SSO clients, scoped roles, subscriptions/payments, полноценного кабинета. Существующие service/repo/transport, DI и внутренний UUID сохранить и развивать. Косметический featers → features выносить отдельно.

При анализе `go test ./...` и `go vet ./...` упали на ForgotPassword: Send вызван с одним аргументом вместо трёх. Session service и password HTTP tests в обычном запуске прошли, весь набор — нет. Lint не выполнил анализ из-за context loading, race завершился ошибкой инструментария. Docker/реальные БД/Redis/SMTP и внешние входы не проверялись. Эти результаты описывают исходное состояние, а не будущую реализацию.

Повторная проверка 4 октября 2026 в текущем checkout: `go test ./...` и `go vet ./...` снова завершаются ошибкой `forgot_password.go:37`; HTTP password tests и session service tests проходят. Lint/race из предыдущего анализа в этом заходе не повторялись. `go-template` находится на `main`, HEAD `4acce0b`, без локальных изменений.

### Подтверждённые замечания к исходному коду (baseline до этапа 1)

| Приоритет | Факт и место | Задача |
| --- | --- | --- |
| P0: блокирует проверки | `ForgotPassword` вызывает `Send` без subject/body и скрывает все ошибки `FindByEmail` как отсутствие пользователя | Этап 1 восстанавливает сборку; 5.2 различает not-found и инфраструктурные ошибки при одинаковом публичном ответе |
| P0: отзыв доступа | `session/repo/redis/UpdateSession` использует безусловный `SET`; между чтением и записью logout может удалить ключ, а refresh — создать его снова | 6.2: атомарный refresh существующей сессии и согласованная модель revoke/logout-all |
| P0: границы сессии | `SessionTTL` и `AbsoluteSessionTTL` используют `SESSION_TTL`; `ValidateSession` принимает равенство deadline и продлевает expiry за absolute deadline | 2.1 и 6.1: отдельные настройки, `now >= deadline`, ограничение expiry/Redis TTL/cookie абсолютным сроком |
| P0: согласованность | `ChangePassword` сначала пишет PostgreSQL, затем отзывает Redis; ошибка Redis оставляет старые сессии после изменения credentials | 6.3: durable invalidation и отказ в доступе при неподтверждённой актуальности |
| P1: сессия браузера | Middleware получает `Extended`, но не обновляет cookie; в проверке сессии не читается актуальный статус пользователя | 5.4 и 6.1: enforcement статуса/auth version и корректный cookie refresh |
| P1: ресурсная защита | Argon2 `Compare` принимает параметры хеша без верхних/нижних bounds и приводит большие числа к узким типам | 6.4: безопасный parser, bounds, fuzz tests, лимит параллельного hashing |
| P1: запуск и эксплуатация | Dockerfile собирает отсутствующий `cmd/finance-app`; shutdown наследует отменённый context; pool не закрывается при неудачном Ping | Этапы 2–3 |

В этапе 1 исправлены сборка/Send, отдельный absolute TTL key, Argon2 parser bounds и lifecycle/container запуск. Остальные session/revocation/CSRF дефекты остаются открытыми. Это анализ кода, а не полный pentest. Все P0 закрываются и проверяются до внешнего production запуска.

## 3. Порядок реализации

Первый исполняемый этап — перенос лучших частей go-template в рабочий Auth, проверка результата и удаление временного reference. Источник уже собран локально; соседний проект больше не требуется. Подробные файлы и действия описаны в [пошаговой реализации](auth-implementation.md). Номера разделов 2–3 и задач 4.2–4.3 сохранены для адресации: их перенос выполняется внутри этапа 1, а не повторяется позднее.

### Этап 0. Зафиксировать архитектуру и границы первого релиза

- [x] 0.1. Самостоятельный single-app backend, cookie/BFF, модульные границы и UUID/app scope — [архитектура](architecture.md), [ADR 001](adr/001-deployment-and-reuse.md).
- [x] 0.2. [Модель угроз](threat-model.md): takeover/replay/CSRF/linking/IDOR/payment forgery/DoS и негативные проверки связаны с подэтапами.
- [x] 0.3. PostgreSQL session ledger/status/auth version, transactional challenge consumption/audit/outbox, fail-closed и authentication context — [ADR 002](adr/002-sessions-and-transactions.md).
- [x] 0.4. Личный billing owner, versioned catalog, hosted checkout одного выбранного позднее provider; независимые role/entitlement/billing настройки и безопасные профили без оплаты — [ADR 003](adr/003-access-and-optional-billing.md).

Готово 6 октября 2026: архитектурные решения приняты, не реализованы runtime-модули. До 12.1 отдельно выбрать merchant requirements/provider; native/SSO/organizations/Telegram commerce требуют выбора расширенного scope. Эти внешние условия не блокируют этап 4.

### Этап 1. Адаптировать лучшее из go-template и удалить reference

- [x] 1.1. Восстановить сборку: завершить reset renderer/subject/body/Send и error handling, сохранив пользовательский HTML. Проверить render и ошибки mailer; новый reset endpoint остаётся задачей 5.2.
- [x] 1.2. Адаптировать инфраструктуру: config validation/tests, independent graceful shutdown, PostgreSQL connect/cleanup, request/context logger, healthchecks и audit contract. Детализация — раздел 2.
- [x] 1.3. Адаптировать dev/prod Docker/Compose, env examples, Task/check commands и CI; проверить toolchain/dependencies и сохранить Auth-specific настройки. Детализация — раздел 3. Выполнять небольшими отдельными изменениями.
- [x] 1.4. Перенести строгий HTTP decoder/validation, Swagger generation и dev/prod policy, сохранив error contract. Детализация — задачи 4.2–4.3; schema/domain остаются следующим этапом.
- [x] 1.5. Принять решение по outbound HTTP client: адаптировать полезную основу с response bounds/redaction/redirect/TLS/SSRF tests либо отклонить wrapper в пользу стандартного transport/официальных SDK. Решение и требования к будущим интеграциям сохранить в документации Auth; не оставлять отложенную зависимость от reference.
- [x] 1.6. Адаптировать полезные backup/restore scripts и задачи под текущий Auth, проверить на disposable DB. Dozzle и SSH deployment оценить отдельно: включить только выбранные компоненты, остальные явно признать ненужными. Автоматический deploy не включать. Позднее этап 14 расширяет уже перенесённые инструменты для новых billing/email workers.
- [x] 1.7. Написать `docs/template-adoption.md`: source commit, матрица «адаптировано / аналог уже есть / отклонено с причиной», рабочие файлы, проверки и ограничения. Перенести полезные operational/copy инструкции в документацию Auth, обновить ссылки в обоих планах.
- [x] 1.8. Временный `docs/reference/go-template/` удалён по явному запросу пользователя после переноса выбранных компонентов. Provenance и решения сохранены в `docs/template-adoption.md`; исходный соседний проект не затронут. Tests/lint и production drill выполнены ранее. 6 октября 2026 dev smoke после CGO fix прошёл на изолированном Compose project; проверочный долг закрыт.

Готово: рабочая инфраструктура Auth проверена, решения/provenance сохранены в `docs/template-adoption.md`, временный reference удалён, следующий этап выполняется исключительно по коду и документации Auth. Незавершённые проверки фиксируются отдельно и не требуют хранения исходного reference. Удаление reference не означает удаление исходного соседнего проекта.

### Раздел 2. Детализация инфраструктуры для подэтапа 1.2

Отдельные подэтапы:

- 2.1. Configuration validation и tests; исправить одинаковый env tag SessionTTL/AbsoluteSessionTTL, проверить сроки и pool limits.
- 2.2. HTTP graceful shutdown с отдельным bounded context; PostgreSQL connect timeout и close-on-Ping-error, сохранив текущие pool settings.
- 2.3. Request ID/context logger, логирование без secrets/query; доверие forwarded IP только настроенному proxy.
- 2.4. Liveness и bounded readiness PostgreSQL + Redis; targeted tests.
- 2.5. Контракт security audit и redaction: структура события, actor/scope, безопасные поля, политика ошибок записи. Durable события добавлять вместе с соответствующими account/access/billing use cases; не откладывать audit административных изменений до этапа 14.

Готово для каждого подэтапа: соответствующие tests, общие доступные checks, example env/docs. Новые login features не входят в этот этап.

### Раздел 3. Детализация окружения и зависимостей для подэтапа 1.3

- 3.1. Согласовать поддерживаемую проверенную Go-версию для dev/CI/builder; восстановить lint/race tooling.
- 3.2. Исправить Dockerfile: ./cmd/auth, корректный binary, platform-aware build и nonroot.
- 3.3. Dev Compose/команды: env, bind paths, Redis password/healthcheck, DB_SERVICE отдельно от DB_NAME, migration ordering.
- 3.4. Prod Compose: изоляция БД/Redis, secret configuration, read-only/capabilities restrictions, TLS reverse proxy assumptions.
- 3.5. Перенести CI и единый check interface; без включения автоматического deployment.
- 3.6. Обновлять библиотеки отдельными группами: HTTP/Swagger, PostgreSQL/Redis, crypto/остальные. Проверять official releases, compatibility и major imports, не копировать go.mod целиком.

При переносе CI закрепить действия/инструменты проверенными версиями, предпочтительно immutable SHA/digests; минимальные workflow permissions и отсутствие production secrets в PR jobs. Добавить secret scanning, dependency/vulnerability checks и проверку drift сгенерированной документации. Локальные команды и CI выполняют один набор обязательных проверок. Исправить чужой import prefix в настройке `gci`; линтер должен соответствовать этому модулю.

Готово: воспроизводимые checks, container build, Compose validation, clean startup и smoke, vulnerability report разобран. Версии в template — кандидаты, не доказательство актуальности или работоспособности Auth.

### Этап 4. Базовая схема и API-контракт

- [x] 4.0. До схемы выполнить отдельный behavior-preserving structural refactor: убрать `internal/core` и `internal/featers`, auth-фичи разместить в `internal/modules/auth`, технические adapters — в узких `internal/infra` пакетах по [архитектуре](architecture.md). Типы/политики/repo queries принадлежат фичам; никаких `common/utils` и циклов импортов. Рукописные code/test файлы ≤150 физических строк, разбиение по use case/ответственности, generated явно исключён. Обновить imports, DI, generator/mock config, документацию путей и добавить `doc.go`/карту навигации. Не менять API/schema/поведение и не смешивать с security fixes. Проверка: существующий `task check` и лёгкий контроль лимита в нём без нового sh-скрипта; дополнительные генерации только если затронуты. Завершение: старых пакетов/imports нет, разработчик видит владельца каждой операции.

Проверить существующие users/profile/password credentials, UUID, constraints, индексы, статусы, soft deletion и правила email ownership. Разделить контактный email и credential при подготовке verification. Редактировать текущие миграции, протестировать чистую схему. Новые identities/access/billing сущности добавлять в эти же SQL-файлы вместе с соответствующим этапом, без лишних таблиц заранее.

- [x] 4.1. Схема/domain/repositories: отдельный contact email, account status/deletion/auth_version, ownership FK и timestamps; проверено на disposable PostgreSQL. Правила применения и ограничения — [schema](schema.md).
- [x] 4.5. Выполнено 8 октября 2026, до 4.4: перенести реализованный код на [согласованную архитектуру](architecture.md) от 7 октября 2026. `app/auth` — сборка/lifecycle, отдельные `config` и `server/http`; `auth/account`, `auth/methods/password`, `auth/session`; model → domain с распределением service results/HTTP DTO по владельцам, email и linked identities — account; audit — отдельный модуль. Не вводить bootstrap, app/wiring, contact/identity/authentication или будущие пустые пакеты. Repositories остаются у фич. 150 строк оставить целевым ориентиром для рукописного Go-кода: делить до 150 только по самостоятельной ответственности, связную операцию можно оставить длиннее без фиксированного потолка. Тесты/generated без лимита, HTML/SQL по смысловой целостности. Убрать автоматический отказ по длине, осмысленно объединить tests/SQL/templates, адаптировать контроль зависимостей. Отдельные access/entitlement/billing/settings добавляются на своих этапах. Не менять API/schema/security поведение или зависимости этим переносом; transaction ownership спроектировать явно, enforcement — этапы 5/6.
- [ ] 4.4. После 4.5: schema/API contract checks, воспроизводимая Swagger generation, соответствие routes/status/DTO/security.

Привести Swagger metadata к универсальному Auth, проверить реальные paths/basePath, DTO/json names, errors и security. Настроить UI для dev/prod и pinned generation. Swagger UI major v2 не означает OpenAPI v3; текущий генератор выпускает Swagger 2.0. Cookie/CSRF ограничения формата документировать; переход на OpenAPI 3 — отдельное решение, не автоматическое обновление.

Строгий JSON decoder и Swagger policy переносятся в 1.4 с сохранением Auth error contract; здесь проверить их соответствие обновлённой схеме/API, не переносить повторно. Любое изменение response status/JSON документировать.

Готово: up/down/up на чистой тестовой БД, API specification валидируется и воспроизводится, routes и DTO совпадают. Swagger, SQL и tests обновляются на всех следующих этапах, не откладываются до релиза.

### Этап 5. Завершить email/password account lifecycle

- 5.1. Email verification: verified_at, ограниченный доступ unverified пользователя, confirm/resend.
- 5.2. Forgot/reset: выдача, доставка, expiry, атомарное одноразовое потребление и согласованность password update.
- 5.3. HTTP logout/logout-all/me, cookie cleanup, список/отзыв собственных сессий.
- 5.4. Blocked/deleted users: запрет нового входа и прекращение существующего доступа.
- 5.5. Смена email: подтверждение нового адреса и свежая аутентификация, уведомление старого адреса, отсутствие возможности перехватить чужой credential. Смена контакта и login identity — явно разные операции.
- 5.6. Удаление аккаунта и политика retention: отзыв сессий/методов, согласованное поведение активной подписки, минимизация PII при сохранении обязательной платёжной истории. Не освобождать identity для незаметного takeover старых привязок.

Для verification/reset challenges определить назначение, владельца, TTL, число попыток и правила замены/одноразовости. Consumption и изменение credentials должны быть согласованы при сбоях. Email URL строится из доверенной конфигурации, не из пользовательского Host; callback/return URL ограничены allowlist. Письма доставляются с bounded retries через outbox или другое проверенное решение. Шаблоны экранируют данные; токены не попадают в логи, analytics и Referrer. Повторная доставка одного письма не создаёт дополнительный grant.

Готово: positive/negative tests и staging smoke с реальной почтой; generic recovery replies не скрывают технические ошибки от безопасных logs/metrics.

### Этап 6. Безопасность текущего входа и сессий

- 6.1. Absolute deadline, boundary expiry, cookie refresh и ротация после чувствительных действий.
- 6.2. По ADR 002 PostgreSQL session ledger/verifier, актуальный user status/auth version на каждом защищённом запросе, atomic refresh/revoke и чувствительная запись с повторной проверкой в SQL transaction. Validate/logout и create/logout-all races не воскрешают session; Redis cache/indexes не являются authority.
- 6.3. Partial SQL/Redis failures при password change/reset: credentials/status/auth_version + audit/outbox одной SQL-транзакцией по ADR 002; dependency failures fail-closed, Redis cleanup после commit не определяет действительность доступа.
- 6.4. Distributed rate limits для login/register/reset, нагрузочные параметры Argon2 и bounds для parsed hashes.
- 6.5. CSRF/origin, fresh authentication, secure cookies/dev HTTPS, SMTP timeouts/TLS, secret redaction.
- 6.6. Registration UNIQUE race и user-created/session-store-failed scenario; стабильные domain errors и повторный вход.
- 6.7. Парольная политика и rehash: разрешить password managers/paste, достаточную длину, проверку скомпрометированных паролей, отсутствие произвольной периодической смены. Изменение Argon2-параметров поддерживает старые hashes и безопасное обновление после успешного входа.

`__Host-session`: Secure, HttpOnly, Path=/, без Domain; безопасный local HTTPS профиль. Cookie/BFF остаётся базовым browser-контрактом; не вводить JWT/refresh tokens без отдельного сценария. При таком расширении обязательны rotation, reuse detection, revocation и изоляция audience. Определить fail-closed поведение для auth/rights при недоступности зависимостей и различать 401/403/503 без раскрытия внутренних ошибок.

CSRF охватывает login, linking и все изменяющие cookie-auth запросы; SameSite не заменяет проверку. CORS использует точный список origins и не допускает wildcard с credentials. Security headers и redirect policy проверяются вместе с реальными email/OIDC/browser flows. Rate limits применяются к account/IP/challenge и стоимости операции, с явным режимом при сбое Redis; proxy headers не дают обходить лимиты.

Готово: concurrency/integration tests с настоящим Redis/PostgreSQL, fault scenarios и HTTP/E2E. Защиты применяются и при добавлении всех последующих methods. Этапы 5/6 делятся по указанным подэтапам, не одним diff.

### Этап 7. Общая модель способов входа и граница SSO

Внутренний user_id независим от email и provider. Добавить identities по проверенным issuer/subject, provider configuration и общие сценарии разрешения пользователя/выдачи сессии; параметры email/OIDC не сводить к искусственно одинаковому API. Email может отсутствовать. Уникальность identity учитывает issuer и регистрацию/область клиента, если провайдер выдаёт pairwise subject; схему уточнить по выбранным адаптерам. Username/display name/непроверенный email не являются стабильным ключом личности.

Различать внешние OAuth/OIDC providers и общий SSO для приложений: go-oidc — client library, не готовый authorization server. Host cookie не обеспечивает общий вход на независимых доменах. Если нужен SSO-профиль, прототип на двух приложениях определяет IdP/server boundary, clients/audiences, local/global logout и authentication context. Готовый IdP (например Keycloak) — вариант, не навязанная замена текущему Go-сервису. Если выбирается свой server, использовать поддерживаемую протокольную реализацию и отдельно проверить server responsibilities. SSO-профиль не блокирует перенос шаблона в независимый проект.

Готово: architecture decision, tests/model, корректная схема и сохранение существующих user UUID. Если credentials передаются IdP, определить transition и совместимость hashes; не развивать два независимых password/reset ядра. Это решение при необходимости можно исследовать раньше, но не переписывать текущую архитектуру без результата прототипа.

### Этап 8. OAuth/OIDC, Telegram и passwordless email

- 8.1. Один внешний OIDC provider через общее ядро: start/callback, browser-bound state, PKCE, nonce где поддерживается, signature/issuer/audience/expiry и replay checks.
- 8.2. Следующие OIDC providers конфигурацией; OAuth-only providers отдельными адаптерами получения стабильной личности из официального API. OAuth не равен стандартизованному подтверждению личности.
- 8.3. Telegram OIDC: вход без email/UserInfo, minimal scopes и проверенные claims.
- 8.4. Email OTP как отдельный метод, лимиты, TTL, одноразовость и безопасное хранение короткого кода. Magic link — последующее расширение с защитой от scanners.
- 8.5. При включении Telegram Mini Apps — отдельный adapter для серверной проверки подписанного `initData`, допустимого возраста `auth_date` и защиты повторного обмена на сессию. `initDataUnsafe` не является доказательством входа. Не смешивать Mini App challenge и web OIDC callback.

Telegram web login опирается на актуальный официальный OIDC flow; legacy widget добавляется только для подтверждённой совместимости. OIDC и Mini Apps identities связывать только по доказанному соответствию идентификаторов, а не по похожим username/sub. Email OTP хранить с keyed verifier и ограниченными попытками: обычный быстрый hash короткого кода недостаточен против offline перебора.

Готово каждого подэтапа: negative tests + реальный staging login. Credentials/callback URLs не публикуются. Не показывать отключённый или ненастроенный provider как рабочий.

### Этап 9. Настройки и привязка методов

- 9.1. Typed env/file policy: enabled providers, registration, public methods discovery без secrets; enforcement при start и callback/verify.
- 9.2. Link/unlink только после проверки контроля аккаунта; не объединять автоматически по совпавшему email, предотвращать чужой linking и удаление последнего метода.
- 9.3. Пользовательские preferences, устройства и sessions; основная кнопка не меняет права.
- 9.4. Несекретные admin settings в БД/API после появления permissions этапа 10. До этого административный endpoint не публиковать без полноценной защиты.

Global/app-specific policy учитывает уже активную SSO-сессию; скрыть кнопку недостаточно. Disable method и revoke sessions — отдельные политики. Issuer/discovery configuration защищена от SSRF. Не потерять последний административный доступ.

Настройки провайдеров и платёжных интеграций принадлежат доверенному administrator/configuration layer; secrets не возвращаются через settings API. Link flow связывается с текущими user/session и свежей аутентификацией, смена пользователя между start/callback его отменяет. Ошибка уникальности identity при конкурирующей привязке не объединяет аккаунты.

Готово: bypass/disabled/linking/last-method tests, public API не раскрывает secrets, policy audit.

### Этап 10. Отдельная настройка ролей и разрешений

Roles → permissions, permissions + resource ownership проверяются backend. Для multi-app профиля добавить applications/app memberships, scoped member/admin и отдельный platform_admin. Организации/приглашения/owner/viewer только при подтверждённой необходимости; расширение scope предусмотрено.

В single-app профиле достаточно одного app scope, member/admin и централизованной deny-by-default policy. Platform admin и управление несколькими apps включаются в расширенном профиле. Roles/permissions расширяемы конфигурацией проекта; API не зависит от жёстко зашитого enum бизнес-ролей. Отдельно проверить query/list endpoints и IDOR, а не только middleware на записи. Bootstrap первого администратора выполняется одноразовым контролируемым operational процессом, без публичного self-promotion endpoint; запрещено случайно удалить последний административный доступ.

Сначала схема и модели, затем access use cases/API и ownership tests, затем защищённые admin settings этапа 9.4. Multi-app профиль дополнительно требует cross-app tests. При IdP связь users — по issuer/subject, не email. Token audience и rights изолируют приложения; произвольные client role/user_id не дают доступ.

Дополнительный подэтап 10.5: отдельные access catalog settings и user role assignments, независимые permissions управления, валидация ссылок и optimistic version. Nonsecret operator config сначала; защищённый settings API только после 13.1. Проверки: custom role, запрещённое permission, конфликт параллельных изменений, last-admin guard. Настройки тарифов/оплаты здесь не находятся.

Готово: no self-promotion/cross-app/cross-owner bypass, актуальный Swagger, audit и fresh authentication для admin изменений.

### Этап 11. Free/Pro и лимиты без платежей

Plans/features/entitlement grants независимо от roles. Продукт, владелец подписки, периоды и источники manual/trial/subscription задаются явно. Перед схемой определить личную/организационную оплату и один продукт/общий пакет; не считать is_pro достаточной моделью.

Free/Pro — демонстрационный каталог, не ограничения ядра. Поддержать произвольные plan/price/features и версии каталога; право на возможность описывается ключом feature, scope и периодом действия. Личный billing account — базовый владелец; team/organization ownership добавляется отдельным профилем с проверками membership. Trial/manual grant не выдаёт роль и имеет audit, источник и срок. Зафиксировать часовой пояс/границы расчётных периодов, правила quota reset и upgrade/downgrade.

Подэтап 11.4: отдельные настройки каталога features/plans/limits и выдачи grants; version/conflict/audit, независимые от role catalog и payment provider. Проверить entitlements-only профиль без payment secrets и запрет admin→paid bypass.

Подэтапы: каталог возможностей и manual grants с expiry; проверки backend; atomic quotas/usage; bounded policy cache/invalidation. Критические permissions не доверяются долгоживущим JWT как единственному источнику.

Готово: Pro не даёт admin, admin не обходит plan, expired grant не действует, конкурентные запросы не обходят квоту. Ограничения задаются каталогом, без финансовой продуктовой логики в общем ядре.

### Этап 12. Платежи и подписки

Выбрать provider по продукту/валютам/юрисдикции. Отдельные подэтапы: серверный checkout; проверенные webhook events и idempotency; renewal/cancel/expiry/grace/refund; reconciliation потерянных событий. Redirect success не подтверждает оплату.

#### Варианты оплаты и граница адаптеров

| Вариант | В базовом шаблоне | Расширение |
| --- | --- | --- |
| Разовая покупка | Серверный order и grant с фиксированным сроком или бессрочным доступом по каталогу | Дополнительные товары и пакеты возможностей |
| Подписка | Периодический доступ, renewal/cancel, окончание оплаченного периода, failed payment/grace | Годовые цены, proration и смена плана по явно заданной политике |
| Free / trial / manual grant | Без платёжного провайдера, expiry и audit | Купоны/промо только с правилами конкуренции и лимитов |
| Web checkout | Один provider, hosted checkout; карты и альтернативные способы — по capabilities | СБП/локальные методы/второй provider после проверки страны продавца, валют и поддержки recurring |
| Telegram Stars | Отдельный включаемый профиль для цифровых товаров внутри ботов/Mini Apps | Подписки Stars по актуальным возможностям Bot API |

Метод оплаты, платёжный provider и бизнес-модель покупки — разные понятия. Интерфейс адаптера описывает поддерживаемые capabilities; unsupported recurring/refund не эмулируется молча. Telegram login на обычном сайте сам по себе не требует Stars; продажи цифровых товаров внутри Telegram используют Stars по [официальным правилам](https://core.telegram.org/bots/payments-stars). Не выбирать Stripe/ЮKassa/другой provider заранее без требований продавца; API/SDK/региональные ограничения проверяются перед соответствующим подэтапом.

#### Подэтапы реализации

- [ ] 12.0. Отдельная billing configuration и permissions управления оплатой; auth-only / entitlements-only / billing-enabled профили. Новый проект без оплаты запускается без provider secrets/connections, payment routes/workers и обязательной billing schema initialization. Выбор schema profile согласовать в 4/12 без destructive flag switches. Остановка новых продаж существующего deployment не отключает webhook/cancel/refund/reconciliation; сохраняются история и действующие grants. Полный shutdown только по runbook после завершения обязательств. Проверить три профиля и sales pause при активной подписке; флаг не обходит entitlement check.
- [ ] 12.1. Billing account, versioned product/price catalog, orders, payment attempts, subscriptions, refunds, event inbox и outbox; точные статусы/переходы и SQL constraints. Суммы — целые minor units с явной валютой/единицей, без float; у XTR свои единицы. Историческая цена покупки неизменна при обновлении каталога.
- [ ] 12.2. Первый web adapter и hosted checkout. Backend определяет owner/price/amount/currency и права на покупку, валидирует return URL; создание заказа и запрос provider защищены от повторов/сбоя между локальной записью и внешним вызовом. Данные карты/PAN/CVV в Auth не хранятся.
- [ ] 12.3. Проверка событий по правилам provider: подпись и raw body, либо предусмотренная официальным API аутентификация/серверная перепроверка. Durable inbox до успешного ACK, уникальность event и charge/order; worker с retries/backoff, журналом ошибок и безопасным replay. IP allowlist не является единственным доказательством оплаты.
- [ ] 12.4. Идемпотентные domain transitions и выдача entitlement; дубли, разные events об одном платеже, unordered и delayed delivery, asynchronous pending/failure, renewal, cancel-at-period-end, expiry/grace. Не выдавать доступ только по `checkout completed`, если деньги ещё не подтверждены.
- [ ] 12.5. Полный/частичный refund и dispute по capabilities, политика отзыва grants, сверка provider state с локальными orders/subscriptions, reconciliation job и alert. Локальная отмена не считается подтверждением отмены recurring у provider.
- [ ] 12.6. Для Telegram commerce: аутентификация Bot API webhook, проверка payload/покупателя/цены/валюты в pre-checkout, grant только после `successful_payment`, дедупликация charge/update, refunds и `/paysupport`. Test environment до включения профиля; pre-checkout approval не подтверждает оплату.
- [ ] 12.7. Документация подключения второго adapter и contract tests; sandbox сценарии: success/failure/pending/refund/retry/out-of-order/lost-event и отсутствие double fulfillment.

Схема и новые capabilities вводятся с соответствующим подэтапом. Базовый релиз не требует реализации всех существующих providers или методов оплаты.

Готово: signatures/duplicates/out-of-order tests, sandbox integration и состояния доступа по period. После downgrade сохранять данные и явно ограничивать features/квоты. Raw provider states преобразуются в согласованную внутреннюю модель, не копируются слепо.

### Этап 13. MFA, кабинет и дополнительные методы

13.1. MFA/TOTP и recovery codes обязательны до включения production administrative endpoints. Enrollment требует fresh auth и подтверждения фактора; TOTP secret защищён at rest, коды восстановления хранятся как verifiers и потребляются одноразово. Challenge ограничен по времени/попыткам, повторный TOTP не допускается в принятом окне. Lost-factor recovery не слабее защиты аккаунта. Session хранит authentication context; MFA проверяется backend, а не только UI. Зависимость: после безопасных сессий этапа 6; admin settings этапов 9.4/10 не публикуются до 13.1.

13.2. Кабинет: профиль, проверенные методы входа, смена email/пароля, сессии, MFA, тариф/лимиты, checkout, отмена подписки и история оплат. Админ API: users/status, role assignments, provider policy и manual grants с audit. Frontend — отдельный adapter; UI реализуется, если выбран в release scope, API обязателен. Поля raw tokens/provider secrets не выдаются пользователю.

13.3. Passkeys/WebAuthn — последующее расширение с verified origin/RP ID и replay protection. SMS/enterprise OIDC/SAML при реальной потребности. User/admin UI использует защищённые APIs и не содержит implementation деталей для пользователя.

Готово: enrollment/recovery/fresh-auth tests, UI не заменяет backend enforcement. Не обещать все дополнительные methods в первом релизе.

### Этап 14. Production release и база для форков

Развить перенесённые в 1.6 backup/restore tooling под итоговую схему и все writers; проверить отдельную test DB restore, минимальные runtime DB privileges, retention/audit/metrics, README/config reference, quick start и upgrade notes. Разделить operational компоненты на небольшие изменения. Ни restore существующей БД, ни auto-deploy не выполняются самим переносом template.

- 14.1. Метрики login/reset/MFA failures, rate limits, session/Redis/DB errors, доставки email и задержки billing events; ограниченная cardinality без email/user/token labels. Security audit фиксирует actor/scope/action/result, хранится отдельно от access logs; alert на опасные изменения и зависшие оплаты.
- 14.2. Runbooks: потеря Redis, недоступность SMTP/provider, утечка/ротация secrets, компрометация аккаунта, восстановление БД и billing reconciliation. Off-site encrypted backups с ограниченным доступом, согласованные RPO/RTO и реальный restore drill. Восстановление DB/Redis не должно возрождать отозванные sessions/challenges; billing сверяется до возобновления обработки.
- 14.3. Документы `README`, configuration reference, extension guide, security policy, release/upgrade notes. Конкретные API examples и поддерживаемые deployment profiles.
- 14.4. Перенос в тестовый продукт с новым module path/name, отдельными credentials, собственной ролью, тарифом и business feature. Общий auth/session flow продолжает проходить тесты; базовый запуск не требует всех optional providers.
- 14.5. Подтверждение release checklist ниже и тег первой поддерживаемой версии; записать результаты/ограничения, а не только отметить наличие инструментов.

Готово: clean checkout стартует по документации, migrations/API/Swagger/security checks и staging smoke подтверждены, exact dependency versions зафиксированы, выбран release scope, tag соответствует поддерживаемым функциям. Дальнейшие schema changes после production идут отдельными миграциями.

## 4. Перенос из go-template

Исторические пути в матрице описывают go-template на зафиксированном commit; рабочие решения и файлы Auth перечислены в [template-adoption](template-adoption.md). Матрица ниже исполняется целиком в этапе 1: инфраструктура 1.2, окружение 1.3, HTTP/Swagger 1.4, HTTP client 1.5, operations 1.6, документация 1.7. Старые номера в колонке обозначают подробные требования, а не перенос в будущих этапах. После 1.8 вместо исходников использовать рабочие файлы Auth и `docs/template-adoption.md`.

| Компонент и источник в go-template | Действие для Auth | Этап |
| --- | --- | --- |
| `internal/infra/config/config.go`, `config_test.go` | Расширить validation текущей конфигурации session/Redis/SMTP/providers; перенести подход к tests | 2.1 |
| `internal/transport/http/server/server.go` | Адаптировать отдельный shutdown context; timeouts уже есть | 2.2 |
| `internal/infra/postgres/postgres.go` | Connect deadline и Close при неудачном Ping; сохранить Auth pool options | 2.2 |
| `middleware/request.go`, `infra/logger/context.go` | Request ID/context logger и redaction; route templates вместо чувствительных URL paths | 2.3 |
| `router/router.go`, `router_test.go` | Liveness/readiness и Swagger policy; дополнить readiness Redis | 2.4, 4 |
| `httpx/request.go`, `request_test.go` | Body limit, Content-Type, single JSON value, unknown fields и DTO validation; сохранить error contract | 4 |
| `deploy/Dockerfile.dev`, `.prod`, `.dockerignore`, `.air.toml` | Сборка `cmd/auth`, проверенная Go version, multi-platform, nonroot и минимальный runtime | 3.1–3.4 |
| `compose.dev.yml`, `compose.prod.yml` | Раздельные профили, readiness/migration ordering; дополнить Redis/SMTP и secrets | 3.3–3.4 |
| `Taskfile.yml`, `.github/workflows/ci.yml` | Единый интерфейс через `Taskfile.yml`; tests/lint по умолчанию, остальные checks отдельно по риску | 3.5 |
| Swagger tasks и защищённый UI | Pinned generator, reproducible docs, отключение dev endpoints в prod | 4 |
| `pkg/client.go`, `client_test.go` | Адаптировать безопасную основу либо отклонить wrapper с обоснованием; дальнейшие SDK integrations независимы от reference | 1.5 |
| `deploy/scripts/postgres-*.sh` | Адаптировать backup/restore сейчас; расширить под итоговые writers на этапе 14 | 1.6 |
| `README.md` | Перенести полезные quick start/operations/copy инструкции в Auth docs | 1.7 |
| `compose.logs.yml`, deployment workflow | Включить выбранный optional component либо отклонить с причиной; auto-deploy off | 1.6 |

Перенести всё полезное отсутствующее после проверки применимости: config validation/tests, shutdown, bounded DB connect, request/context logger, healthchecks/tests, HTTP validation, Swagger policy/generation, dev/prod Docker/Compose, check commands/CI, backup tooling и документацию. Матрица каждого компонента: перенесён / аналог уже есть / адаптирован / неприменим с причиной.

Не копировать весь go.mod/структуру слепо. Сохранить Auth error contract, pool/session settings и credentials flows. Решение по HTTP client и optional operations завершить в этапе 1; исходники для будущих задач в reference не оставлять. Provenance хранить краткой документацией, а не полной копией другого проекта.

Template объявляет Go 1.27.1, chi 5.3.2, pgx 5.10.0, http-swagger/v2 2.0.2, x/crypto 0.52.0. Это прочитанные dependency declarations, не подтверждение latest или совместимости Auth. Официальные версии/docs проверять перед реализацией обновлений через Context7/первичные источники.

## 5. Сквозные требования к БД, Swagger и безопасности

БД: FK/UNIQUE/CHECK/NOT NULL/indexes по реальным запросам, timestamps/retention, стабильный user UUID, корректная область identities/roles/subscriptions. Владелец billing не задаётся неоднозначными nullable колонками без ограничений. Up/down текущей схемы согласованы, clean install проверен; опубликованная production схема в будущем обновляется миграциями.

Swagger: каждый implemented route имеет точный path/method, DTO, required/limits, security/permission, errors/statuses и safe examples. Cookie/CSRF, redirects и webhook описаны явно. Generated docs pinned и проверяются на drift/validity/routes contract. Не документировать будущие endpoints как уже рабочие.

Checks: formatters, build, vet, lint, unit/integration tests; race для concurrency; vulnerability checks и container review. Реальные providers/mail/payment sandbox проверяются отдельно. Известные ошибки инструментария исправить, не считать отсутствием code findings. Govulncheck не доказывает отсутствие всех уязвимостей.

Fault tests: revoked session не возрождается; blocked user не сохраняет доступ; SQL/Redis partial failure; expired/replayed challenges; registration uniqueness; incorrect state/nonce/signature/audience; disabled method callback; чужие identities/resources/scopes; последнее средство входа/admin; Pro/admin separation; concurrent quotas; payment duplicate/reorder/reconciliation. Logs/responses не содержат tokens/passwords/secrets.

### Переносимость и обновления зависимостей

- [ ] Убрать наследие `financial-intelligence` из module/imports, Docker binary, Swagger metadata и конфигурации; отдельно проверить `featers` и чужие lint prefixes. Rename выполняется отдельным проверяемым изменением.
- [ ] Продуктовые roles, feature keys, prices, branding, mail templates и URLs расширяются без изменения механизмов проверки личности/сессии/платежа. Integration interfaces небольшие и соответствуют реальным сценариям; не создавать plugin framework без необходимости.
- [ ] Описать места расширения и ownership API/schema. Новый feature не обращается напрямую к cookies/Redis keys и не дублирует authorization.
- [ ] Зафиксировать стратегию template updates: upstream tags/changelog, небольшие тематические commits, перенос security fixes в форки, схема разбора merge conflicts. Копирование один раз не обеспечивает будущие обновления автоматически.
- [ ] Добавить регулярные dependency PRs через выбранный updater: minor/patch отдельно от major/Go/tooling; никаких слепых `@latest` обновлений в prod. PR проходит unit/integration/race/build/docs/container checks; crypto changes дополнительно проверяют старые hashes и migration/rehash.
- [ ] SDK payment/OIDC и provider API versions закреплены отдельно; обновление library не означает незаметную смену remote API version. Breaking changes сопровождаются upgrade notes и rollback plan.
- [ ] Доказать переносимость на втором небольшом проекте: новый name/module, одна custom permission, новый plan/feature и изменённые письма. Запуск/тесты воспроизводятся без credentials первого проекта.

### Общий Definition of Done подэтапа

Задача имеет проверяемый diff, обновлённые schema/config/API docs и содержательные positive/negative tests по своему риску. Выполнены доступные обязательные checks; результаты и не проверенные интеграции записаны. Нет secrets/PII в diff, errors и logs. Незавершённый provider/endpoint выключен. Сам факт успешных mock tests не заменяет PostgreSQL/Redis concurrency и staging verification.

### Checklist первого production релиза

- [ ] Закрыты все P0, threat model и review не содержат неразобранных критических замечаний.
- [ ] `go test ./...`, vet/build/lint, уместные race/fuzz и integration checks проходят на закреплённом toolchain; vulnerability/secret/container findings разобраны.
- [ ] Чистая тестовая БД проходит up/down/up; deployment использует минимальные DB privileges и согласованную схему. Рабочая БД пользователя не сбрасывалась для проверки.
- [ ] Email verification/reset/change, OTP, Telegram login/link/unlink и session management проверены в staging; disabled methods не обходятся через callback.
- [ ] Session revoke/logout-all/block/password reset остаются корректными при гонках и частичных сбоях PostgreSQL/Redis; сроки cookie/Redis согласованы.
- [ ] Permissions/ownership/app scope и MFA администраторов enforced backend; bootstrap/recovery/последний admin проверены.
- [ ] Plans/grants/quotas проверены независимо от roles; выбранный payment adapter проходит sandbox и reconciliation, нет повторной выдачи доступа.
- [ ] Prod configuration не включает dev mail endpoint, слабые defaults или открытые PostgreSQL/Redis; публичный ingress работает через TLS.
- [ ] Restore drill, alerts и incident runbooks проверены; retention и правила обработки account deletion/refund определены.
- [ ] Новый проект запускается по copy guide; обновления зависимостей и перенос upstream fixes документированы.
- [ ] Release notes перечисляют поддерживаемые профили. SSO, Mini Apps/Stars, второй provider и прочие extensions заявляются только после собственных acceptance tests.

## 6. Текущий статус

Этап 0 завершён 6 октября 2026: architecture, threat model, ADR 001–003 и независимые access/entitlements/billing settings. Этап 1: перенос и cleanup завершены; provenance — [template-adoption](template-adoption.md). Tests/lint и production migration/restore/negative drill прошли ранее. 6 октября dev image build и isolated startup/SMTP smoke после CGO fix прошли; технический долг dev-запуска закрыт. Новые auth/session/RBAC/MFA/billing возможности не реализованы, baseline P0 ещё требуют этапов 5/6. Подэтапы 4.0 и 4.1 завершены: модульная структура, лимит файлов, схема/domain/repositories. Перенос 4.5 выполнен; следующий шаг — 4.4: API/schema contract.

Проверка этого шага: `docker build -f deploy/Dockerfile.dev -t auth:devcheck .`; `AUTH_TEST_IMAGE=auth:devcheck AUTH_TEST_APP_ENV=dev AUTH_SMOKE_ONLY=true task check-integration` — exit 0. Проверены dev startup, migration up, runtime DB connection, PostgreSQL/Redis readiness, liveness, Swagger disabled (404), локальная SMTP отправка в Mailpit. Disposable project `auth-check-1791315226-3825` и его volumes удалены runner; существующая БД не затронута. Это не полный integration/backup drill или external SMTP delivery. На этапе 0 изменения были документационными; tests/lint/security scan и GitHub CI тогда повторно не запускались. Проверка local Markdown links и `git diff --check` прошла. Release checks этапа 14 сохраняются.

| Этап | Статус | Зависимость / результат |
| --- | --- | --- |
| 0. Архитектура и scope | Завершён 06.10.2026 | architecture, threat model и ADR 001–003; runtime реализация впереди |
| 1. Перенос и удаление reference | Перенос и cleanup завершены | Tests/lint и prod drill ранее; dev startup/SMTP smoke прошёл 06.10.2026 |
| 2. Инфраструктура | Выполнено в 1.2 | Durable audit sink — отдельно по ADR; здесь только контракт |
| 3. Toolchain/окружение/deps | Адаптировано в 1.3 | Dev startup/SMTP smoke после CGO fix подтверждён 06.10.2026 |
| 4. Структура/схема/API | 4.0, 4.1 и 4.5 завершены | Согласованное дерево реализовано; далее 4.4 |
| 5. Account lifecycle | Частичная основа | Register/login/change уже есть; verification/reset/lifecycle не завершены |
| 6. Безопасность сессий | Частичная основа | Cookie/Argon2/Redis есть; подтверждённые дефекты не исправлены |
| 7. Identities / SSO boundary | Не начат | После 0, 4, 6; общий SSO optional |
| 8. Telegram/OIDC/OTP | Не начат | После 5–7; Mini Apps optional |
| 9. Policy/linking | Не начат | После 7–8; admin API зависит от 10 и 13.1 |
| 10. Roles/permissions | Не начат | После 4, 6; single-app first, multi-app optional |
| 11. Plans/entitlements | Не начат | После 10 |
| 12. Payments | Не начат | После 11 и выбора provider; Stars зависит от commerce profile |
| 13. MFA/cabinet | Не начат | 13.1 после 6 и до публикации admin API; остальное по API готовности |
| 14. Release/переносимость | Не начат | После обязательных модулей и checklist; документация ведётся по ходу |

Текущий порядок: 0, 1.1–1.8, 4.0/4.1/4.5 завершены → 4.4 → 5/6 → 7/8 → 9/10 → 11/12 → 14. Разделы 2–3 и перенос 4.2–4.3 входят в первый этап. Решения этапа 0 принимаются до зависимых задач; 13.1 выполняется сразу после 6 до включения любых production admin действий. После 1.8 все следующие этапы используют только рабочий Auth и его документацию.

### Результат 4.5 — 8 октября 2026

Перенесены реализованные фичи на согласованное дерево: app/auth, config, server/http, auth/account/domain, auth/methods/password, auth/session и отдельный audit domain/port. Типы credentials — domain; configs, inputs/results и ports — service; HTTP DTO остаются transport. Repositories локальны фичам, будущие пакеты не созданы. Legacy CreateUser остаётся атомарным и отмечен как cross-feature write; целевой transaction ownership описан в architecture, фактическая lifecycle/security реализация — 5/6.

Сборка отделена от Run; signal context приходит из main. Cleanup выполняется в обратном порядке, после остановки сервера, идемпотентно и при ошибке частичного startup. HTTP Shutdown использует независимый deadline и принудительное закрытие при его истечении. Лимит 150 строк заменён ориентиром, проверки import boundaries адаптированы. Tests объединены по операциям, SQL по ответственности, reset HTML цельный с прежними байтами.

Проверено: `task go:fmt`, `task check` (tests + lint), `task swagger` и `git diff --check`. Generated Swagger JSON/YAML/Go совпадают с исходным контрактом. Lifecycle tests проверяют active-request drain, независимый shutdown deadline/close, serve failure, cleanup order/idempotency и восстановление logger при раннем startup failure. Полный Docker/backup/security drill и реальные PostgreSQL/Redis fault scenarios повторно не запускались; SQL/schema/dependencies и рабочая БД не менялись. Следующий шаг — 4.4.

### Архитектура согласована — 7 октября 2026

Пользователь утвердил feature-first дерево с явными domain/service/repository/transport, методами password/emailotp/oidc/telegram и общими account/session/mfa. Contact и внешние linked identities входят в account; отдельный authentication-модуль заранее не создаём. App/auth собирает приложение и управляет ресурсами; config и server/http выделены отдельно. Access, entitlement, billing и audit — отдельные модули; product settings остаются у владельцев, billing опционален. Полное дерево, правила зависимостей/транзакций и пример фичи — [architecture](architecture.md).

Историческая запись согласования: на 7 октября это было документационное решение, не выполненный refactor. Реализация 4.5 завершена 8 октября, см. результат выше. Жёсткий лимит заменён ориентиром 150 строк при осмысленном разделении; связные операции могут быть длиннее без фиксированного потолка. Тесты/generated не ограничиваются, HTML/SQL сохраняют смысловую целостность. Существующая проверка будет изменена в 4.5. Номер 4.5 добавлен без перенумерации уже выполненных задач, выполняется перед 4.4. Текущий код/SQL/API и рабочие данные не менялись.

### Результат 4.1 — 7 октября 2026

Обновлены исходные SQL up/down, account/contact models и password PostgreSQL repositories. Email вынесен в `auth.user_emails`, добавлены `auth_version`, timestamps/trigger и ownership FK; soft deletion сохраняет уникальность контакта. Регистрация атомарна, конкурентный duplicate email сохраняет существующий error contract. Email validation теперь принимает только адрес без display name/обёртки/комментариев; неправильный input возвращает существующую ошибку валидации. DTO/routes не менялись.

Проверено: `task go:fmt`, `task check` (tests + lint, 0 issues), `AUTH_SCHEMA_TEST_DATABASE_URL=<disposable localhost fixture> go test ./internal/modules/auth/password/repository/postgres -run TestPostgresSchema -count=1 -v`. PostgreSQL 18.6: SQL up/down/up, repository round-trip, timestamps, CHECK/FK/UNIQUE, rollback, cascade, soft-deleted email reservation, concurrent registration — PASS. Созданный временный контейнер удалён; рабочая БД не затронута. Новый sh-скрипт не добавлен, полный инфраструктурный drill не повторялся.

Исходная миграция несовместима с уже применённой 000001 без отдельного переноса данных; reset рабочей БД не выполнялся и не разрешён этим этапом. Account status/version enforcement, verification, SQL session ledger и audit/outbox остаются этапами 5/6. Правила — [schema](schema.md). Следующий шаг — 4.4; этап 4 целиком ещё не закрыт.

### Результат 4.0 — 6 октября 2026

Существующий Auth перенесён в `internal/modules/auth`: account/email/password/session и audit contract. Технический код — в `internal/infra`, общий HTTP transport — в `internal/transport/http`, aggregated runtime config — в `internal/app/config`. Feature config и session issuance result принадлежат model, service не импортирует concrete adapters или другой session service. Карта путей и правила расширения — [architecture](architecture.md). `core`/`featers` удалены, пользовательские staged `.serena` файлы сохранены без изменений.

Большие tests разбиты по прежним сценариям; change-password input/validation отделены от handler. HTML reset-письма разделён на header/content и соединяется до html/template parsing: исходные байты сохранены. Все рукописные Go/HTML исходники ≤150 строк; обычный test `internal/app/layout_test.go` проверяет лимит и основные import boundaries. Новых shell-скриптов/пустых будущих интеграций нет.

Проверено: `task fmt`, `task swagger`, `task check` — успешны, lint 0 issues. Swagger JSON совпадает с исходным контрактом, включая schema names; для этого использованы документированные `swaggertype`/`@name`. SQL/schema/dependencies и HTTP поведение не менялись; runtime Docker/SMTP/race/security scan повторно не запускались. Новые session security/lifecycle функции не добавлены, baseline P0 остаются задачами 5/6. Следующий шаг — **4.1**, не повторный перенос инфраструктуры.

### Dev tooling — уточнение 6 октября 2026

По явному запросу добавлен `.air.toml` для `./cmd/auth`; Air `v1.67.4` закреплён только в dev image, Go/HTML watch и graceful interrupt/restart настроены по документации. Production image и application dependencies не менялись. Tmp binary вынесен в отдельный writable volume; integration runner подготавливает mountpoint для readonly source bind.

Taskfile приведён к формату предоставленного примера: отступы 4 пробела, списки cmds, русские секции/описания, namespaced `dev:*`, `migrate:*`, `go:*`, `check:*`, `prod:*`; `backup`/`restore` отдельно. Старые публичные имена — aliases. `task check` всё ещё только tests + lint; rollback/restore guards сохранены. Worker/seeds/log dashboard/auto-deploy/reset из примера не добавлены.

Проверено: Task list/dry-run, shell syntax, `git diff --check`, dev image build и `AUTH_TEST_IMAGE=auth:aircheck AUTH_TEST_APP_ENV=dev AUTH_SMOKE_ONLY=true task check:integration` — успешны. Первый запуск выявил отсутствующий tmp mountpoint; исправление проверено повторным smoke. API действительно стартует через Air, readiness/liveness/локальная SMTP отправка прошли. Тестовый project `auth-check-1791317880-20730` и volumes удалены; существующая БД не затронута. File-change reload и signal-drain под активной нагрузкой отдельно не проверялись; полный tests/lint/security/backup drill не повторялся для dev config changes. Следующий функциональный шаг остаётся 4.1.

## Источники

Текущий код Auth и go-template — источник выводов о проекте. Telegram/OIDC/платёжные правила и webhook semantics повторно проверены 4 октября 2026 через Context7 и официальную документацию; остальные ссылки — материалы для ADR/реализации, а не подтверждение готовности интеграций:

- Telegram OIDC: https://core.telegram.org/bots/telegram-login
- Telegram Mini Apps validation: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
- Telegram Stars: https://core.telegram.org/bots/payments-stars
- Webhook verification/delivery semantics на примере Stripe (не выбор provider): https://docs.stripe.com/webhooks
- Authentication review: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OAuth security: https://www.rfc-editor.org/rfc/rfc9700.html
- Go OIDC: https://github.com/coreos/go-oidc
- Keycloak: https://www.keycloak.org/docs/26.8.0/server_admin/
- WebAuthn: https://www.w3.org/TR/webauthn-3/

## Режим проверок после уточнения пользователя

Обычный шаг: `task check` — tests + lint. Не повторять полный набор после каждой мелкой правки. Race/security/Swagger/Compose/container/integration запускать отдельно только для затронутого риска или release gate; vet/build/format не дублировать отдельными checks поверх tests/lint. CI — tests/lint, security и image build; integration/race не запускаются автоматически на каждый push. В `deploy/scripts` оставлены только backup core, host restore wrapper и один integration runner; Swagger проверяется Task recipe без отдельного shell-файла.
