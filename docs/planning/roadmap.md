# План реализации универсального production Auth-шаблона

Обновлено 10 октября 2026. Рабочий проект: `/Users/inforberi/Desktop/Projects/auth`, ветка `feat/register-ai`. Исходный анализ: HEAD `5e8f5e5` и незакоммиченные изменения reset HTML/HTTP-ошибок. Источник инфраструктурных улучшений: `/Users/inforberi/Desktop/Projects/go-template`, main, изученный HEAD `4acce0b`.

## 1. Назначение и правила

Auth — переиспользуемый Go-шаблон, который можно скопировать или форкнуть, настроить и доработать под другой продукт. Текущий выпуск: аккаунты, email/password, email-код, Telegram, выбранный OAuth/OIDC-провайдер, сессии, роли/permissions, MFA администратора и UI. Оплата, тарифы и entitlements — отдельное будущее расширение, не обязательная часть этого выпуска.

### Согласованный scope — 11 октября 2026

Сначала завершить Auth и UI без оплаты: упростить доработку 6.7 → закончить lifecycle/security → методы входа и linking → роли → защищённые admin API/MFA → сохраняемые Auth settings → UI → финальная приёмка/перенос. Номера существующих задач сохраняются для истории; актуальный порядок — [implementation](implementation.md#текущий-выпуск-auth-роли-и-ui).

Этапы 11/12 и billing-зависимые части остальных этапов не выполняются сейчас. Не создавать для будущей оплаты schema/routes/workers/config или пустые adapters. Общий SSO, multi-app/организации, Mini Apps/Stars и passkeys также отложены. UI текущего выпуска не ждёт ни одного из этих расширений. Уже сделанный код не удаляется автоматически при изменении плана.

Полноценность означает завершённые согласованные сценарии, а не максимальное число механизмов. Для дополнительной настройки, зависимости или подсистемы нужна конкретная текущая польза. Сохранить hash/resource bounds, SQL constraints, немедленный отзыв, проверки полномочий и транзакционные гарантии.

### Настраиваемые способы входа

- Независимо включать password, email OTP, Telegram и каждый реализованный OAuth/OIDC provider. Public registration — отдельный переключатель. Реализовать до UI через operational config, сохраняемые settings и UI — в конце.
- Для password registration отдельно выбрать email verification: disabled / optional / required. При disabled письмо автоматически не отправлять; при required до подтверждения не выдавать доступ к защищённым функциям, оставив только ограниченные verification/recovery/logout сценарии. Не подделывать verified_at и не превращать Telegram/OIDC login в обязательный password+email flow.
- Backend проверяет разрешённый метод при start/login/verify/callback/link, а не только скрывает кнопку. При отключении провайдера незавершённый callback не обходит запрет; уже сохранённая identity не удаляется.
- Выключенный метод не требует своих provider secrets/подключений. Не разрешать конфигурацию без рабочего административного способа входа/восстановления. Смена настроек — protected permissions/MFA/fresh-auth/audit; не разрешать публичному запросу выбирать менее строгую политику.
- Роли определяют доступ независимо от способа входа. Админка требует разрешений и MFA; сам выбор OAuth, Telegram или password не даёт admin. Сайт и админка — комбинации настроек одного сервиса, не отдельные архитектуры, multi-app или общий SSO.
- До реализации settings явно определить применение новой verification policy к existing users/sessions. Отключение метода само по себе не отзывает все существующие сессии: отзыв — отдельная явная операция; block/status/version enforcement сохраняется.

Примеры целевых конфигураций:

| Использование | Методы входа | Подтверждение email | Доступ |
| --- | --- | --- | --- |
| Сайт | password + выбранный OAuth/OIDC | отдельно для password: optional или disabled | пользовательские роли |
| Сайт с подтверждением почты | password | required | защищённые функции после подтверждения |
| Сайт без паролей | Telegram и/или email OTP | email OTP сам доказывает владение адресом; Telegram не требует email | пользовательские роли |
| Админка | выбранные разрешённые методы | по согласованной политике | admin permissions + MFA |

Таблица описывает будущие настройки, не уже работающие runtime-профили. UI только показывает применяемую сервером политику.

### Второй фактор

Первый шаг — разрешённый метод входа, второй — дополнительное доказательство. Password+TOTP или password+SMS — два фактора; SMS вместо пароля — самостоятельный способ входа, не двухфакторка. Под телефоном пока подразумевается SMS-код; phone-only login не включать автоматически в текущий scope.

- Основной второй фактор: TOTP, совместимый с Google Authenticator и другими TOTP-приложениями. UI показывает QR/manual key, подключение завершается только после проверенного кода. Google Authenticator не Gmail; для проверки TOTP не нужны Gmail API, Google OAuth или SMS provider.
- MFA policy: отключено / пользователь подключает добровольно / обязательно для заданных ролей; админские операции текущего выпуска требуют MFA, переключатель не должен обходить эту защиту. Allowed factors настраиваются отдельно от primary login methods.
- SMS как дополнительный optional factor: включать только после выбора SMS provider и проверки delivery. До этого нет provider-зависимостей, dummy adapters, phone-login routes или обязательных secrets. Для административного MFA текущего выпуска не использовать SMS как замену TOTP/recovery codes.
- Подключение/смена номера или TOTP и отключение фактора требуют подтверждения владения и текущего доступа; не допускать замены фактора одним украденным cookie. Нужны limits/expiry, привязка challenge к login/user и защита replay/concurrent consume.
- Если MFA требуется, первый шаг выдаёт только короткое ограниченное challenge-состояние, а не полноценную session/admin access. Финальный шаг повторно проверяет актуальность account и policy; смена метода входа не обходит локально требуемый MFA.
- Одноразовые recovery codes для потери устройства, отдельный protected recovery при их отсутствии. Password reset/email verification не отключают MFA. Не считать код по почте или обычный login через Google доказательством второго фактора.
- В A7 UI: подключить/отключить фактор, ввод второго кода при login, recovery codes и настройки MFA policy. Не добавлять push confirmation/passkeys/универсальный MFA framework сейчас.

Основания: [Google Authenticator](https://support.google.com/accounts/answer/1066447?hl=ru) и [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html). SMS имеет риски SIM swap/переноса номера и не приравнивается к TOTP по нашей admin policy. TOTP тоже не является phishing-resistant; соответствие уровню NIST не заявляется.

Основной сценарий — отдельный экземпляр Auth для каждого проекта, с собственной БД, secrets и пользователями. Общий аккаунт и SSO между независимыми проектами — отдельный профиль, который требует решения об IdP и прототипа; копирование шаблона само по себе не означает общий вход. Первый релиз работает с одним приложением; границы app scope проектируются так, чтобы позднее добавить несколько приложений без потери user UUID. Не вводить полноценную multi-tenancy, организации и свой OAuth server ради абстрактной универсальности.

Вход отвечает на вопрос «кто пользователь», permissions — «что ему разрешено», entitlements — «какие функции доступны по тарифу». Pro не даёт административные права; admin не получает Pro автоматически. Роли и подписки могут различаться по приложениям.

Уточнено 10 октября: поддержать ручное создание/приглашение пользователей и назначение ролей/разрешений через защищённый backend API; UI добавляется в конце. Оплата опциональна и может обрабатываться отдельным сервисом, но приём подтверждённых событий и API доступа остаются в Auth. Возможность закрепляем границами модулей и этапами ниже; сейчас не добавляем пустые interfaces, таблицы, endpoints или обязательные подключения ради будущего сценария.

Работать непосредственно в указанном каталоге и ветке; не выполнять реализацию в прежнем worktree. Незакоммиченные изменения пользователя сохранять. Один рабочий заход — один этап или подэтап, отдельный проверяемый diff; не смешивать инфраструктуру, обновление зависимостей, новые login methods и billing в одно изменение.

**Миграции:** проект не в production. Для текущей разработки редактировать существующие up/down SQL-файлы напрямую, новые миграции не создавать. Итоговую схему проверять на чистой отдельной тестовой БД, включая up/down/up. Не сбрасывать существующую локальную БД и не удалять данные без явного разрешения. Переписывание SQL-файла не обновляет уже применённую схему автоматически. После первого production выпуска дальнейшие изменения выпускаются отдельными миграциями.

**Качество:** каждый завершённый этап выполняется с production требованиями: безопасная конфигурация, корректная обработка ошибок, актуальные API docs и содержательные проверки. Production-готовность всего сервиса подтверждается совокупностью критериев релиза, а не завершением одного этапа. Не проверенные интеграции и ограничения явно фиксируются.

**Постоянное правило разработки:** читаемый код с ясными обязанностями пишем сразу, во всех следующих этапах, а не откладываем качество на рефакторинг. Дополнительные время и токены допустимы, если нужны для корректного решения; искусственная дробность и лишние абстракции не нужны. Правила файлов, HTTP-сценариев и обработки ошибок закреплены в [AGENTS.md](../../AGENTS.md).

По запросу пользователя реализован инфраструктурный перенос этапа 1; reference уже удалён, dev smoke проверяется отдельно. Остальные задачи ниже — будущая реализация, их наличие в плане не означает готовность кода. После каждого подэтапа обновлять статус, фактические проверки и ограничения в этом файле.

### Постоянное правило производительности

Во всех следующих этапах сразу проектировать корректные и экономные пути выполнения, а не оставлять известные узкие места до этапа 6.8. Это часть приёмки каждой фичи, не разрешение на преждевременные абстракции или ослабление безопасности.

- До реализации определить частый путь, количество обращений к SQL/Redis и границы работы: входные размеры, concurrency, deadlines, pagination/batch, retries. Не добавлять N+1, unbounded очереди/draining, лишние обращения к зависимостям и записи без изменения состояния.
- Для новых/изменённых SQL запросов проверить соответствие predicates/order индексам, lock order и конкурентные гарантии. В частых и фоновых путях не допускать проходов по всей большой таблице ради небольшой/пустой партии; LIMIT сам по себе не гарантирует малый scan. При таком риске проверить план на репрезентативных данных.
- Учесть совокупные connection/CPU/RAM бюджеты API и workers при нескольких экземплярах, bounded отказ/восстановление зависимостей и контролируемые 429/503. Не увеличивать пулы автоматически вместо измерений.
- Сохранять Argon2, немедленный revoke/version/status enforcement, atomicity и SQL constraints. Для кеша отдельно определить допустимую устарелость и поведение при отказе; кеш сессий не включать ради обещания большей нагрузки.
- Проверять затронутый риск, не повторять все дорогие тесты после каждой правки. Записывать условия, latency/throughput и ограничения измерений; количество пользователей и настроенные лимиты не считать доказательством capacity.

Текущая измеренная база — [performance](../operations/performance.md): короткий SQL-only прогон около 10159 session reads/s на 100000 синтетических сессий, 32 читателя/pool 10, p95 5.4ms. Это не полный API RPS и не число поддерживаемых активных пользователей. Default 128 HTTP handlers/2 hash operations на экземпляр и 1000 login attempts/min для проекта — защитные бюджеты, а не подтверждённая производительность. Полная mixed/multi-instance приёмка остаётся открытым этапом 6.8b.

### Результат, к которому идём

- Безопасный жизненный цикл аккаунта: регистрация, подтверждение/смена email, вход, восстановление, смена пароля, привязка/отвязка методов, блокировка и удаление.
- Сессии с немедленным отзывом, управлением устройствами и защитой чувствительных действий; MFA для административного доступа.
- Независимые account/auth methods, session, access, entitlement, billing и infrastructure; внешние identities принадлежат account. Продуктовые функции, цены, роли и лимиты задаются настройками/расширениями проекта.
- Версионированный API, SQL-схема, проверяемые dev/prod окружения, наблюдаемость, backup/restore и воспроизводимый CI.
- Инструкция переноса в другой проект, пример адаптации и отдельный процесс безопасного обновления зависимостей.

Текущий набор шаблона: email/password + optional/required verification/reset, email OTP, Telegram web login, выбранный OAuth/OIDC provider, account linking, custom roles/permissions, MFA администратора и UI. Методы независимо включаются настройками. Billing/entitlements и другие расширения описаны ниже только для будущего, не создаются сейчас и не блокируют выпуск Auth. Выключенная или непроверенная интеграция не считается поддерживаемой.

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

Первый исполняемый этап — перенос лучших частей go-template в рабочий Auth, проверка результата и удаление временного reference. Источник уже собран локально; соседний проект больше не требуется. Подробные файлы и действия описаны в [пошаговой реализации](implementation.md). Номера разделов 2–3 и задач 4.2–4.3 сохранены для адресации: их перенос выполняется внутри этапа 1, а не повторяется позднее.

### Этап 0. Зафиксировать архитектуру и границы первого релиза

- [x] 0.1. Самостоятельный single-app backend, cookie/BFF, модульные границы и UUID/app scope — [архитектура](../architecture.md), [ADR 001](../adr/001-deployment-and-reuse.md).
- [x] 0.2. [Модель угроз](../threat-model.md): takeover/replay/CSRF/linking/IDOR/payment forgery/DoS и негативные проверки связаны с подэтапами.
- [x] 0.3. PostgreSQL session ledger/status/auth version, transactional challenge consumption/audit/outbox, fail-closed и authentication context — [ADR 002](../adr/002-sessions-and-transactions.md).
- [x] 0.4. Личный billing owner, versioned catalog, hosted checkout одного выбранного позднее provider; независимые role/entitlement/billing настройки и безопасные профили без оплаты — [ADR 003](../adr/003-access-and-optional-billing.md).

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

- [x] 4.0. До схемы выполнить отдельный behavior-preserving structural refactor: убрать `internal/core` и `internal/featers`, auth-фичи разместить в `internal/modules/auth`, технические adapters — в узких `internal/infra` пакетах по [архитектуре](../architecture.md). Типы/политики/repo queries принадлежат фичам; никаких `common/utils` и циклов импортов. Рукописные code/test файлы ≤150 физических строк, разбиение по use case/ответственности, generated явно исключён. Обновить imports, DI, generator/mock config, документацию путей и добавить `doc.go`/карту навигации. Не менять API/schema/поведение и не смешивать с security fixes. Проверка: существующий `task check` и лёгкий контроль лимита в нём без нового sh-скрипта; дополнительные генерации только если затронуты. Завершение: старых пакетов/imports нет, разработчик видит владельца каждой операции.

Проверить существующие users/profile/password credentials, UUID, constraints, индексы, статусы, soft deletion и правила email ownership. Разделить контактный email и credential при подготовке verification. Редактировать текущие миграции, протестировать чистую схему. Новые identities/access/billing сущности добавлять в эти же SQL-файлы вместе с соответствующим этапом, без лишних таблиц заранее.

- [x] 4.1. Схема/domain/repositories: отдельный contact email, account status/deletion/auth_version, ownership FK и timestamps; проверено на disposable PostgreSQL. Правила применения и ограничения — [schema](../schema.md).
- [x] 4.5. Выполнено 8 октября 2026, до 4.4: перенести реализованный код на [согласованную архитектуру](../architecture.md) от 7 октября 2026. `app/auth` — сборка/lifecycle, отдельные `config` и `server/http`; `auth/account`, `auth/methods/password`, `auth/session`; model → domain с распределением service results/HTTP DTO по владельцам, email и linked identities — account; audit — отдельный модуль. Не вводить bootstrap, app/wiring, contact/identity/authentication или будущие пустые пакеты. Repositories остаются у фич. 150 строк оставить целевым ориентиром для рукописного Go-кода: делить до 150 только по самостоятельной ответственности, связную операцию можно оставить длиннее без фиксированного потолка. Тесты/generated без лимита, HTML/SQL по смысловой целостности. Убрать автоматический отказ по длине, осмысленно объединить tests/SQL/templates, адаптировать контроль зависимостей. Отдельные access/entitlement/billing/settings добавляются на своих этапах. Не менять API/schema/security поведение или зависимости этим переносом; transaction ownership спроектировать явно, enforcement — этапы 5/6.
- [x] 4.4. Выполнено 9 октября 2026: API contract tests для routes/status/DTO/errors/cookie metadata и воспроизводимая Swagger generation. SQL schema проверена в 4.1; ограничения текущей безопасности — [API-контракт](../api/contract.md).

Привести Swagger metadata к универсальному Auth, проверить реальные paths/basePath, DTO/json names, errors и security. Настроить UI для dev/prod и pinned generation. Swagger UI major v2 не означает OpenAPI v3; текущий генератор выпускает Swagger 2.0. Cookie/CSRF ограничения формата документировать; переход на OpenAPI 3 — отдельное решение, не автоматическое обновление.

Строгий JSON decoder и Swagger policy переносятся в 1.4 с сохранением Auth error contract; здесь проверить их соответствие обновлённой схеме/API, не переносить повторно. Любое изменение response status/JSON документировать.

Готово: up/down/up на чистой тестовой БД, API specification валидируется и воспроизводится, routes и DTO совпадают. Swagger, SQL и tests обновляются на всех следующих этапах, не откладываются до релиза.

### Этап 5. Завершить email/password account lifecycle

- 5.1. Реализовано и локально проверено 9 октября: email verification, ограничение sensitive routes, confirm/resend, encrypted outbox/audit/worker и fail-closed limits. Внешний SMTP и browser HTTPS staging smoke остаются приёмкой перед release; [детали](../features/email-verification.md).
- 5.2. Реализовано и локально проверено 9 октября: forgot/reset, encrypted outbox/worker, version-bound одноразовый SQL challenge, atomic password update/auth_version/revoke/audit. SQL ledger — необходимая часть 6.2/6.3, не закрытие всего этапа 6. Внешний SMTP/browser staging остаётся приёмкой; [детали](../features/password-recovery.md).
- 5.2r. Выполнен и проверен 9 октября: рефакторинг читаемости после 5.2, до новой функциональности 5.3. Дерево папок и app/auth из app.go/account.go/run.go сохранены; смешение обязанностей и лишняя дробность уменьшены. Детализация ниже и в [пошаговой реализации](implementation.md#52r-рефакторинг-читаемости--выполнен-9-октября).
- 5.2h. Выполнен и проверен 10 октября: независимые HTTP-сценарии разделены, общий механизм ошибок подключён с локальными правилами фич. Порядок и результаты — ниже и в [пошаговой реализации](implementation.md#52h-http-сценарии-и-общий-механизм-ошибок--выполнен-10-октября).
- 5.3. Реализовано и локально проверено 10 октября: HTTP me/logout/logout-all/list/revoke-own, независимый публичный UUID, cookie cleanup, bounded keyset pagination и атомарный caller/ownership/revoke/audit. Новые mutations защищены exact Origin allowlist; общая CSRF/CORS policy остаётся 6.5. Результат и ограничения ниже.
- 5.4. Реализовано и локально проверено 10 октября: active/not-deleted enforcement, внутренний block/unblock с expected version, atomic status/version/revoke/challenge cleanup/audit, нейтральный login при stale issuance. Deleted account не разблокируется; admin HTTP ещё не публикуется. Подробности и границы ниже.
- 5.5. Смена email: подтверждение нового адреса и свежая аутентификация, уведомление старого адреса, отсутствие возможности перехватить чужой credential. Смена контакта и login identity — явно разные операции.
  - 5.5a–d реализованы, 5.5e-local проверен: opt-in backend request/confirm/report/recover для password-профиля, SQL authority и mail outbox, отдельные HTTP scenarios/Swagger/тесты. Внешняя приёмка 5.5e-staging остаётся открытой; следующий backend-шаг 5.6; [контракт](../features/email-change.md).
  - Перед 5.5d выполнен рефакторинг навигации 10 октября: input/result рядом со сценариями, явные verification/recovery filenames, `ValidationResult` и `PrepareVerification`, отдельные mail/worker и SQL forgot/reset ответственности. Дерево и публичное поведение сохранены; текущая карта — в [архитектуре](../architecture.md). Проверены formatter, `task check` (тесты и линтер), `task check:api` и whitespace diff. Новая функциональность этим пунктом не закрывается.
  - До подтверждения нового адреса действующим остаётся старый. Запрос связан с user/session/auth_version; при завершении повторно проверить активность аккаунта, актуальность запроса и уникальность адреса внутри транзакции. Подтверждение не создаёт сессию; изменение login email отзывает прежние сессии и связанные recovery/verification challenges.
  - На прежний подтверждённый адрес отправить уведомление при запросе смены и при её завершении с действием «Это не я». Если прежний адрес не был подтверждён, не выдавать ему право блокировать аккаунт; поведение этого профиля определить до реализации, не приравнивать контакт к доказательству личности.
  - Пока смена не завершена, действие «Это не я» отменяет запрос, инвалидирует его токены и отзывает все сессии. Отмена не делает скомпрометированный пароль безопасным: сообщить о необходимости восстановления доступа; автоматический вход не выдавать.
  - Если смена уже завершена, действие блокирует аккаунт, увеличивает auth_version, отзывает сессии и инвалидирует незавершённые security challenges. Не возвращать прежний email и не разблокировать аккаунт автоматически; отдельный процесс восстановления должен доказать владение аккаунтом, устранить скомпрометированные credentials и определить безопасный адрес. Этот процесс — обязательная зависимая задача, а не незащищённый публичный unblock.
  - Защитный токен одноразовый, purpose-bound и привязан к конкретной смене и прежнему подтверждённому адресу; хранить только digest (raw token только в encrypted mail payload), default окно 24h от запроса, подтверждение 30m. Не инвалидировать защиту самим confirm, обычной сменой пароля/logout-all или дополнительной сменой email: атакующий не должен выключать предупреждение. После защищённого восстановления инвалидировать прежние полномочия, чтобы старое письмо не блокировало восстановленный account; этот transition реализован в password-профиле 5.5d.
  - GET по обеим ссылкам только открывает страницу; изменения выполняются POST после явного подтверждения. URL из доверенной конфигурации, no-store/referrer protection, токены не логировать; лимиты и нейтральные ошибки. Страницы UI остаются финальным этапом, backend-контракт реализуется сейчас.
  - Отмена/подтверждение/защитная блокировка сериализуются по аккаунту и запросу: при гонке сначала отмена запрещает подтверждение, сначала подтверждение приводит к блокировке, а не потерянной отмене. State/version/revoke/challenge cleanup/audit и постановка уведомлений в существующий encrypted outbox атомарны. Проверить replay/expiry/replacement, чужие токены/занятый адрес, blocked/deleted, stale session и параллельные операции, rollback при audit/outbox failure и восстановление после инцидента.
- 5.6. Удаление аккаунта и политика retention: отзыв сессий/методов, согласованное поведение активной подписки, минимизация PII при сохранении обязательной платёжной истории. Не освобождать identity для незаметного takeover старых привязок.
  - 5.6a и 5.6b-worker локально реализованы: внутреннее version-bound deletion, cleanup/revoke/scrub, bounded retention из env 30/30/180, новый UUID/unverified contact без старых прав, no-restore tombstone и blocked-before-deletion reservation hold. Worker раз в минуту/до 100 rows на таблицу/SKIP LOCKED; открытый email минимизируется при release, отдельного HMAC store нет. Без публичной ручки и новой миграции. Restore reconciliation, ban-erasure policy и billing lifecycle до оплачиваемого профиля открыты; настройки переносим в финальные backend settings/UI. [Контракт](../features/account-deletion.md#согласованная-политика-и-env).
- 5.7. Ручное создание пользователя/приглашение: account use cases независимо от публичной регистрации; создание не выдаёт сессию, роли, платный доступ или отметку verified. Стабильный UUID, контакт по выбранному профилю с уникальностью email, безопасная активация с одноразовым purpose-bound приглашением: установка собственного пароля либо доказательство владения включённым методом входа. Не передавать общий пароль администратору. Повторная операция не создаёт дубль и не объединяет существующий аккаунт по email. Административный transport включить только после 10 + 13.1 + CSRF/fresh-auth; публичное registration=false не блокирует разрешённое ручное добавление. Invitation delivery использует существующий outbox после появления этого сценария, не дублирует mail infrastructure.

5.7a реализован и локально проверен 10 октября: внутренний idempotent provisioning, pending account, distinct invitation, optional POST password activation с Redis/shared hash budgets и atomic owner/version/expiry/audit enforcement. Роли/session/grants не выдаются; block/delete и activation marker предотвращают обход. Delivery/GC используют текущие workers, профиль выключен по умолчанию. 5.7b реализован 11 октября: отдельный idempotent перевыпуск для прежнего pending UUID, atomic replacement/audit, durable cooldown и Redis quotas. Admin transport после permissions/MFA и non-password proof после 7/8. [Контракт](../features/invitations.md).

Для verification/reset challenges определить назначение, владельца, TTL, число попыток и правила замены/одноразовости. Consumption и изменение credentials должны быть согласованы при сбоях. Email URL строится из доверенной конфигурации, не из пользовательского Host; callback/return URL ограничены allowlist. Письма доставляются с bounded retries через outbox или другое проверенное решение. Шаблоны экранируют данные; токены не попадают в логи, analytics и Referrer. Повторная доставка одного письма не создаёт дополнительный grant.

5.7c-local реализован 11 октября: дополнительный выключенный по умолчанию профиль ручного создания с генерируемым сервисом временным паролем и TTL. Первый вход даёт только одноразовое ограниченное полномочие установки пароля, без session; pending status сохраняется до atomic complete. Смена отменяет временные credentials/полномочия, не подтверждает email и не выдаёт роли. Приглашение остаётся основным вариантом; безопасная внешняя operator выдача/admin transport после 10/13.1, настройки/UI в конце. MFA и будущие alternate methods остаются отдельными gates. Однократная выдача, idempotency/reissue, env/API и проверки — [контракт](../features/temporary-passwords.md), [implementation](implementation.md#57c-опциональный-временный-пароль).

Готово: positive/negative tests и staging smoke с реальной почтой; generic recovery replies не скрывают технические ошибки от безопасных logs/metrics.

### 5.2r. Рефакторинг читаемости — выполнен 9 октября

Согласовано 9 октября 2026. Это уборка существующей реализации, не новая архитектура или оптимизация гарантий авторизации. Папки/пакетные границы сохраняются; существующие config.go/ports.go/domain models не объединяются автоматически только потому, что короткие. Ориентир 150 строк сохраняется без жёсткого gate. Число файлов не обязано увеличиваться.

1. Проверить references и убрать реально неиспользуемое: SessionID, старый session creation wrapper с version=0 и отдельный UpdatePasswordHash, используемый тестами. Перевести tests на реальные version-bound create и atomic change/reset; не удалять рабочие операции или ослаблять проверку доступа.
2. Объединить искусственно разнесённое: session/service/created.go с results.go; session/transport/http constructor/type из middleware.go с действием Auth из auth.go. Session domain errors оформить с правильным названием вместо вводящего в заблуждение token.go. Не создавать файлы по одному helper/type ради симметрии.
3. Разделить только разные обязанности: middleware account HTTP отдельно от verification handlers, DTO рядом с endpoint; Forgot и Reset в файлах соответствующих сценариев; password repo constructor в repository.go, credential reads в credentials.go, mutation рядом с change/reset. Общую passwordPolicyError перенести в существующий HTTP errors.go. SMTP transport отделить от MIME message building. SQL security transaction оставить последовательной и целостной, не дробить каждую команду на helper.
4. В существующих app.go/account.go/run.go упростить New до именованных шагов в тех же файлах. Account assembly возвращает только account dependencies; связывание account+password registration явно в app.go, общий запуск/остановка delivery workers в run.go. Сохранить partial startup cleanup, shutdown order и завершение workers до DB/Redis close. Не вводить infrastructure.go/session.go/password.go/delivery.go, bootstrap, wiring или DI framework только ради этого refactor.
5. Исправить mocks: CreateSessionAtVersion проверяет auth_version; ChangePassword проверяет current session, expected hash и new hash, а не перенаправляется на старый UpdatePasswordHash. Использовать существующий httpx.IP вместо дубликатов peerIP/recoveryIP; policy не доверяет forwarded headers. Упростить receiver names и форматирование плотного SQL без изменения запросов/locks/expiry.
6. Redis сохраняется, роли хранилищ по ADR 002 не меняются. Неподключённый старый Redis session adapter оценить отдельно по usages/назначению: не возвращать как fallback, не объявлять новой реализацией кеша и не удалять автоматически только потому, что основной путь SQL. Оставленное legacy явно отделить в документации от действующего пути.
7. Проверить сохранение поведения: formatter + task check, целевые lifecycle/contract tests. Swagger generation/drift только при затрагивании annotations/DTO; disposable SQL fixture при изменении транзакционной реализации. Не менять API/status/JSON, schema, env, dependencies, security policy или рабочие данные. Если обнаружен behavioral defect, зафиксировать отдельной задачей, не маскировать fix под refactor. Обновить карту файлов и результаты; затем 5.3. Load/оптимизация — отдельный 6.8, cache-only extension — 6.9.

### 5.2h. HTTP-сценарии и общий механизм ошибок — выполнен 10 октября

Сохраняем архитектуру и дерево папок; продолжаем рефакторинг читаемости до новых endpoints 5.3.

1. Разнести account resend/confirm и password forgot/reset: обработчик, request DTO и Swagger — рядом в файле сценария; общий Handler/constructor/response — в `handler.go`. Middleware остаётся feature-local. Проверить остальные рукописные файлы; разделять самостоятельные обязанности, объединять искусственно разнесённое, не создавать файл на каждую функцию.
2. Убрать смешение в account service и change-password input/error mapping; сделать config validation понятной последовательностью именованных проверок в существующих файлах. `app/auth` остаётся из трёх файлов; связанные repository-операции и lifecycle не дробим без необходимости. 150 строк — смысловой ориентир, тесты без лимита.
3. Общий mapper и запись ответа — в `internal/transport/http/httpx`; сопоставление через `errors.Is`/`errors.As`, поддержка wrapped/typed errors, status/code/message/headers, явный fallback операции. Правила — в `transport/http/errors.go` каждой фичи, с наборами для разных сценариев. Без глобального каталога domain errors, импорта фич в httpx, reflection, строкового matching и HTTP-знаний в business logic.
4. Короткие вызовы обработки ошибок вместо повторяющихся switches. Сохранить текущие API-контракты, нейтральные recovery-ответы, 401/403/429/500/503 и остальные существующие статусы, коды/сообщения и `Retry-After`. Обязательная input-валидация остаётся явной; health имеет отдельный контракт. Единообразное однократное логирование безопасных полей: операция/request ID/публичный код/статус, без raw errors, тел запросов и секретов. Security audit отдельно.
5. Приёмка: mapper table-tests (direct/wrapped/typed/unknown, приоритет правил, fallback и заголовки), redaction/logging и HTTP contract-тесты; formatter, `task check`, Swagger drift при переносе аннотаций. Не добавлять проверки ради проверок: SQL/E2E только при затрагивании соответствующих контрактов. Без изменений API, schema/env/dependencies, роли Redis и строгих session/recovery гарантий. После фактической приёмки — 5.3; производительность остаётся задачей 6.8.

Подэтап согласован 9 октября, реализован и проверен 10 октября. Ручки resend/confirm и forgot/reset разнесены вместе с DTO/Swagger; общие handler-типы и response остались в handler.go. Change-password input-файл объединён со сценарием; правила ошибок вынесены в errors.go/recovery_errors.go. Account service разделён по сценариям, config проверяется именованными шагами; app/repositories/lifecycle не раздроблены.

Общий httpx mapper поддерживает wrapped sentinel и typed predicates (errors.As), явные fallback, headers и приоритет правил; запись ответа и безопасное логирование отделены от сопоставления. Применён к account/password/recovery/session и dev send-mail. Health отдельно. Проверено: task go:fmt, task check (tests + lint, 0 issues), task check:api (все три артефакта совпадают), git diff --check. Добавлены mapper/logging/header tests, session gate/context/cookie-refresh и 20 router error-contract сценариев. API/SQL/env/dependencies, Redis и security гарантии сохранены. DB/container/external SMTP/browser/load проверки не повторялись; production readiness не заявляется. Следующий шаг — 5.3.

### Этап 6. Безопасность текущего входа и сессий

Согласовано 9 октября 2026: **PostgreSQL + Redis сохраняются**. Базовый профиль — строгий SQL отзыв, без принятия сессии по устаревшему кешу. Redis обслуживает распределённые limits и кеширование с явно допустимой устарелостью; не считается заменой enforcement. Предложенные 5 секунд задержки отзыва не утверждены. Оптимизировать измеренные узкие места, не добавлять cache-only validation заранее. Политика — [ADR 002](../adr/002-sessions-and-transactions.md).

- 6.1. Absolute deadline, boundary expiry, cookie refresh и ротация после чувствительных действий.
- 6.2. По ADR 002 PostgreSQL session ledger/verifier, актуальный user status/auth version на каждом защищённом запросе, atomic refresh/revoke и чувствительная запись с повторной проверкой в SQL transaction. Validate/logout и create/logout-all races не воскрешают session; Redis cache/indexes не являются authority.
- 6.3. Partial SQL/Redis failures при password change/reset: credentials/status/auth_version + audit/outbox одной SQL-транзакцией по ADR 002; dependency failures fail-closed, Redis cleanup после commit не определяет действительность доступа.
- 6.4. Distributed rate limits для login/register/reset, нагрузочные параметры Argon2 и bounds для parsed hashes.
- 6.5. CSRF/origin, fresh authentication, secure cookies/dev HTTPS, SMTP timeouts/TLS, secret redaction.
- 6.6. Registration UNIQUE race и user-created/session-store-failed scenario; стабильные domain errors и повторный вход.
- 6.7. Парольная политика и rehash: разрешить password managers/paste, достаточную длину, проверку скомпрометированных паролей, отсутствие произвольной периодической смены. Изменение Argon2-параметров поддерживает старые hashes и безопасное обновление после успешного входа.
  - 6.7-local и последующий A1 cleanup: сохранены domain-политика новых паролей, строгий parser и CAS rehash после login; файловый blocklist/env/24-value baseline удалены. Проверка утечек отложена и не заявляется текущей гарантией. [Профиль и ограничения](../operations/password-security.md); длина password-only/MFA, UI paste и mixed load проверяются отдельно, соответствие NIST не заявляется.
- 6.8. Приёмка производительности базового профиля: согласовать active sessions/RPS/login-reset rates/P95-P99/resource budget; измерить несколько API instances, SQL session validation/refresh, Argon2 и Redis limits. По результатам настроить bounded pools/concurrency/deadlines, refresh frequency, кеш некритичных чтений и защиту от cache stampede. Проверить overload, SQL/Redis timeout и восстановление без возврата revoked доступа; не заявлять поддержку произвольной нагрузки.
  - 6.4a/6.8a реализованы 10 октября: shared hash/login/HTTP budgets, trusted proxy/cookie/header/deadline bounds, monotonic CAS refresh/no-op, indexed range cutoffs, отдельный paced GC, readiness coalescing и production log sampling. Локальная correctness/race/Redis/100000-row SQL приёмка — [performance](../operations/performance.md). 6.8b mixed/multi-instance load и release metrics/alerts остаются открытыми.
- 6.9. Опциональное расширение, не release gate базового профиля: только если 6.8 подтверждает необходимость, предложить новый ADR для cached session validation. До реализации согласовать максимальную задержку revocation, неподлежащее продлению время SQL proof, race/failover/restore и bounded fallback/invalidation retry. Чувствительные записи сохраняют SQL enforcement. По умолчанию выключено; 5 секунд и любые новые env/settings не добавлять без согласования.
- 6.8c. В финальную нагрузочную приёмку включить retained heap/allocations, goroutines, Go GC и RSS на повторяемых циклах нагрузки/отдыха, отменах, сбоях зависимостей и shutdown. До неё проверить освобождение ресурсов при рефакторинге. Критерии и безопасная диагностика — пункт 6.8c в [implementation](implementation.md); отсутствие утечек не объявлять без измерений.

В A2 проверена локальная реализация account/session lifecycle: expiry/absolute deadline, SQL authority/status/version, conditional refresh, rotation/fresh-auth, reset/change/block/delete и отзыв с audit. CSRF/Origin и HTTP failure mapping реализованы. Browser/multi-tab, реальные dependency faults/restore и mixed load остаются release gates A8; роли/MFA/admin enforcement — A4/A5. Подробные local/release статусы — в [implementation](implementation.md).

`__Host-session`: Secure, HttpOnly, Path=/, без Domain; безопасный local HTTPS профиль. Cookie/BFF остаётся базовым browser-контрактом; не вводить JWT/refresh tokens без отдельного сценария. При таком расширении обязательны rotation, reuse detection, revocation и изоляция audience. Определить fail-closed поведение для auth/rights при недоступности зависимостей и различать 401/403/503 без раскрытия внутренних ошибок.

CSRF охватывает login, linking и все изменяющие cookie-auth запросы; SameSite не заменяет проверку. CORS использует точный список origins и не допускает wildcard с credentials. Security headers и redirect policy проверяются вместе с реальными email/OIDC/browser flows. Rate limits применяются к account/IP/challenge и стоимости операции, с явным режимом при сбое Redis; proxy headers не дают обходить лимиты.

Готово: concurrency/integration tests с настоящим Redis/PostgreSQL, fault scenarios и HTTP/E2E. Защиты применяются и при добавлении всех последующих methods. Этапы 5/6 делятся по указанным подэтапам, не одним diff.

Переиспользование: отдельный deployment на каждый проект, малые интерфейсы и repositories внутри фич; app только связывает реализации. Роли/methods/payments независимы. JWT, микросервисы и универсальный plugin framework не обязательны. Единый SSO для нескольких проектов — отдельно по 7.3, не скрытая multi-tenancy текущего шаблона.

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

Согласовано 11 октября: в текущем single-project профиле предусмотреть подключаемый каталог permissions внешнего backend и необязательных шаблонов ролей. Один версионируемый формат для ручного файла и последующего защищённого API; сначала явный импорт с просмотром изменений, без автоматического назначения/расширения прав или перезаписи настроенных ролей. Стабильные ключи и понятные группы/названия позволяют вручную собрать роль и отдельно назначить её пользователям. Импорт не может подменить системные полномочия или обойти guards административных изменений; неизвестные/отсутствующие возможности закрыты по умолчанию. Backend данных применяет права к действиям, строкам и полям, включая read/write/filter/sort/export; Auth не становится универсальным proxy или интерпретатором внешних схем. Межсервисное доверие и актуальность прав — отдельный согласуемый контракт, не следствие импорта. Реализация и приёмка — 10.5a/b в [implementation](implementation.md); API-получение при конкретной интеграции, без sync workers/auto-discovery/SSO/multi-app сейчас.

В single-app профиле достаточно одного app scope, member/admin и централизованной deny-by-default policy. Platform admin и управление несколькими apps включаются в расширенном профиле. Roles/permissions расширяемы конфигурацией проекта; API не зависит от жёстко зашитого enum бизнес-ролей. Отдельно проверить query/list endpoints и IDOR, а не только middleware на записи. Bootstrap первого администратора выполняется одноразовым контролируемым operational процессом, без публичного self-promotion endpoint; запрещено случайно удалить последний административный доступ.

Сначала схема и модели, затем access use cases/API и ownership tests, затем защищённые admin settings этапа 9.4. Multi-app профиль дополнительно требует cross-app tests. При IdP связь users — по issuer/subject, не email. Token audience и rights изолируют приложения; произвольные client role/user_id не дают доступ.

Дополнительный подэтап 10.5: отдельные access catalog settings и user role assignments, независимые permissions управления, валидация ссылок и optimistic version. Nonsecret operator config сначала; защищённый settings API только после 13.1. Проверки: custom role, запрещённое permission, конфликт параллельных изменений, last-admin guard. Настройки тарифов/оплаты здесь не находятся.

Уточнение 10.3: backend одноразовой первоначальной настройки и восстановления первого супер-админа подготовить до финального UI. При первом открытии админки свежей установки показывать мастер, затем только обычный login. Мастер не доступен «первому посетителю»: требуется одноразовое доказательство operator control установки через защищённый setup secret/локальную operator operation, без предустановленного пароля. Конкретный механизм выбрать перед реализацией, это пока не новые env или endpoints. Завершение атомарно создаёт пользователя, назначает защищённую системную роль супер-админа, пишет audit и durable initialized marker. До административного доступа завершить MFA enrollment 13.1 и доказательство контроля контакта по выбранной политике; незавершённый мастер не выдаёт admin session. Конкурентное завершение допускает ровно одного первого супер-админа. Marker хранится в PostgreSQL, не в браузере/env и не выводится из отсутствия admin: перезапуск, удаление/блокировка/потеря последнего admin не открывают setup снова. Root encryption key остаётся внешней operational настройкой.

Уточнение 10.3-recovery: забытый пароль супер-админа обычно восстанавливается через стандартное почтовое recovery, без изменения роли, auto-login, снятия административной блокировки или обхода MFA. Для отсутствующей почты/недоступного SMTP предусмотреть отдельно управляемую break-glass CLI-команду/runbook с доступом оператора к deployment: явный существующий target UUID, подтверждение целевой среды, безопасный ввод нового секрета без argv/logs, password policy, атомарная замена credentials + auth_version/revoke/challenge cleanup + audit. Не сбрасывать БД, не создавать другого супер-админа, не менять роли/verified email/setup marker. Не вводить постоянный env override или reset при каждом старте; если потребуется env/file authorization, она одноразовая и используется только явной операторской командой. Lost-MFA recovery — отдельная процедура 13.1 с проверенным доказательством, не автоматическое отключение фактора при смене пароля. Проверить unauthorized invocation, repeat/replay, wrong target/environment, audit rollback и сохранение последнего effective admin.

Уточнение 10.5/10.6 для универсального UI: создавать собственные роли с постоянным ID/уникальным key, понятным названием, описанием и выбранными permissions; редактировать каталог отдельно от ручного назначения/отзыва ролей у пользователя. Permissions имеют зарегистрированный backend-контракт: произвольный текст из UI не создаёт новое разрешённое действие. Каталог расширяется проектом без enum бизнес-ролей. Системный супер-админ и зарезервированные ключи защищены от переименования/подмены/удаления; повышение до супер-админа — отдельное явно защищённое полномочие, не следствие создания роли с похожим именем. Изменение permissions роли тоже проходит delegation/last-effective-admin/version/audit guards. Роли не назначают paid entitlement и не меняют account status.

Подэтап 10.6: административное управление пользователями и доступом поверх 5.7/10.1–10.5. Раздельные permissions создания/приглашения, просмотра пользователей, назначения ролей и изменения каталога; администратор не может выдавать полномочия за пределами собственной явно разрешённой области делегирования. Основной способ назначения — роли; прямые user permission grants допустимы как включаемый сценарий с источником/scope/expiry/audit, без неявного override-framework. Проверять effective permissions после назначения/отзыва, запрет self-promotion и last-admin guard также для прямых grants. Backend доступен без UI; будущая панель использует те же use cases/API.

Предварительные API-контракты (не реализованы и не добавляются в текущий Swagger): POST `/api/v1/admin/users` — создание/приглашение; GET `/api/v1/admin/users` — bounded список; управление `/api/v1/admin/users/{id}/roles` и optional `/permissions`; GET `/api/v1/admin/users/{id}/access` — effective permissions. Методы/DTO назначения/отзыва и permissions зафиксировать перед 10.6. Domain account не зависит от access/billing: роли назначаются отдельной операцией, не свободными privileged полями create-user DTO. Audit содержит actor/target/scope/action/result, а secrets приглашений не раскрываются через список пользователей.

Готово: no self-promotion/cross-app/cross-owner bypass, актуальный Swagger, audit и fresh authentication для admin изменений.

### Этап 11. Free/Pro и лимиты без платежей

Plans/features/entitlement grants независимо от roles. Продукт, владелец подписки, периоды и источники manual/trial/subscription задаются явно. Перед схемой определить личную/организационную оплату и один продукт/общий пакет; не считать is_pro достаточной моделью.

Free/Pro — демонстрационный каталог, не ограничения ядра. Поддержать произвольные plan/price/features и версии каталога; право на возможность описывается ключом feature, scope и периодом действия. Личный billing account — базовый владелец; team/organization ownership добавляется отдельным профилем с проверками membership. Trial/manual grant не выдаёт роль и имеет audit, источник и срок. Зафиксировать часовой пояс/границы расчётных периодов, правила quota reset и upgrade/downgrade.

Подэтап 11.4: отдельные настройки каталога features/plans/limits и выдачи grants; version/conflict/audit, независимые от role catalog и payment provider. Проверить entitlements-only профиль без payment secrets и запрет admin→paid bypass.

Подэтап 11.5: API текущего плана/доступных features/срока действия/лимитов и отдельное protected управление manual grants. Показываемое в UI «оплачен/Pro» выводится из действующих entitlement grants и их периодов, не хранится в `account.status` и не делает пользователя admin. Payment/subscription state и account status имеют разных владельцев. Manual/trial/payment источники не перетирают друг друга; отзыв одной покупки затрагивает только связанные grants. Проверить expiry, несколько источников и отключённый payment module без утраты ручного управления доступом.

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
- [ ] 12.8. Optional external-payments профиль: платёжный сервис владеет checkout/provider secrets/financial state и проверяет provider; Auth владеет users/access/entitlements и сохраняет внутренний endpoint приёма событий, ориентир POST `/api/v1/internal/billing/events`. Service identity с ограниченной областью grant delivery, аутентификация/защита replay, server-side соответствие user UUID/app/order/plan/period и allowlisted event types; browser cookie, client redirect и запрос «сделать paid» не являются подтверждением. Source + event ID + business operation IDs, версии переходов, durable inbox и идемпотентный локальный grant/revoke + audit + receipt/outbox до ACK. Межсервисной SQL-транзакции нет: sender outbox, retries, подтверждение/повтор и reconciliation устраняют потерю доставки; duplicate/unordered/refund/expiry не выдают доступ дважды и не отзывают чужие manual grants. Контракт transport/auth/versioning определить до реализации, не копировать raw provider schema. В Auth остаются public access/plan API и admin manual grants; external adapter не требует provider secrets/полной payment schema. Проверить отсутствие admin promotion/account unblocking через событие и выключенный endpoint в auth-only профиле. Отдельный сервис сейчас не создаём.

Схема и новые capabilities вводятся с соответствующим подэтапом. Базовый релиз не требует реализации всех существующих providers или методов оплаты.

Готово: signatures/duplicates/out-of-order tests, sandbox integration и состояния доступа по period. После downgrade сохранять данные и явно ограничивать features/квоты. Raw provider states преобразуются в согласованную внутреннюю модель, не копируются слепо.

### Этап 13. MFA, кабинет и дополнительные методы

13.1. MFA/TOTP и recovery codes обязательны до включения production administrative endpoints. Enrollment требует fresh auth и подтверждения фактора; TOTP secret защищён at rest, коды восстановления хранятся как verifiers и потребляются одноразово. Challenge ограничен по времени/попыткам, повторный TOTP не допускается в принятом окне. Lost-factor recovery не слабее защиты аккаунта. Session хранит authentication context; MFA проверяется backend, а не только UI. Зависимость: после безопасных сессий этапа 6; admin settings этапов 9.4/10 не публикуются до 13.1.

13.2. Кабинет: профиль, проверенные методы входа, смена email/пароля, сессии, MFA, тариф/лимиты, checkout, отмена подписки и история оплат. Админ API: users/status, ручное создание/приглашение, role assignments/optional user permissions, provider policy и manual grants с audit; использовать 5.7/10.6/11.5, не создавать второй набор правил. Frontend — отдельный adapter; UI реализуется, если выбран в release scope, API обязателен. Поля raw tokens/provider secrets не выдаются пользователю. При external payments checkout/history/cancel принадлежат платёжному сервису; Auth показывает свой effective access, не становится вторым финансовым ledger.

13.3. Passkeys/WebAuthn — последующее расширение с verified origin/RP ID и replay protection. SMS/enterprise OIDC/SAML при реальной потребности. User/admin UI использует защищённые APIs и не содержит implementation деталей для пользователя.

Готово: enrollment/recovery/fresh-auth tests, UI не заменяет backend enforcement. Не обещать все дополнительные methods в первом релизе.

### Этап 14. Production release и база для форков

Развить перенесённые в 1.6 backup/restore tooling под итоговую схему и все writers; проверить отдельную test DB restore, минимальные runtime DB privileges, retention/audit/metrics, README/config reference, quick start и upgrade notes. Разделить operational компоненты на небольшие изменения. Ни restore существующей БД, ни auto-deploy не выполняются самим переносом template.

- 14.1. Метрики login/reset/MFA failures, rate limits, session/Redis/DB errors, доставки email и задержки billing events; ограниченная cardinality без email/user/token labels. Security audit фиксирует actor/scope/action/result, хранится отдельно от access logs; alert на опасные изменения и зависшие оплаты.
- 14.2. Runbooks: потеря Redis, недоступность SMTP/provider, утечка/ротация secrets, компрометация аккаунта, восстановление БД и billing reconciliation. Off-site encrypted backups с ограниченным доступом, согласованные RPO/RTO и реальный restore drill. Восстановление DB/Redis не должно возрождать отозванные sessions/challenges; billing сверяется до возобновления обработки.
- 14.3. Документы `README`, configuration reference, extension guide, security policy, release/upgrade notes. Конкретные API examples и поддерживаемые deployment profiles.
- 14.4. Перенос в тестовый продукт с новым module path/name, отдельными credentials, собственной ролью, тарифом и business feature. Общий auth/session flow продолжает проходить тесты; базовый запуск не требует всех optional providers.
- 14.4s. В самом конце функциональной реализации добавить сохраняемые Auth settings и server-side policy: независимый выбор password/email OTP/Telegram/OIDC, registration enabled, verification enabled/required после password registration, TTL/cooldown/URL. Required/optional/disabled profiles; не подделывать verified_at, при disabled verification не отправлять автоматическое письмо, required=true/enabled=false отклонять. Проверить existing users/sessions, fail-closed dependencies и последний административный способ входа. OTP/reset/change-email/linking сохраняют собственное доказательство владения почтой.
- 14.4s-local, 16 октября 2026. A6.2a добавил независимый administrative password+MFA intent и existing session/recovery reuse с повторной SQL authority/readiness проверкой; [контракт](../features/auth-settings.md). Публичные переключатели ещё не применяются: A6.2b — enforcement всех consumers/commit, A6.2c — только затем settings API. A6/14.4s целиком не завершены; внешняя pre-ui-backend приёмка обязательна.
- 14.4s-local, A6.2b. Startup/persisted policy и enforcement публичных методов подключены: early admission после лимитов и final SQL shared lock против policy update, verification profiles и primary context. Не добавлен policy polling/cache/session-middleware query. Старые sessions не получают скрытый logout-all; admin intent независим. Settings API остаётся A6.2c с adapter readiness checks, secrets/UI и внешняя приёмка открыты. [Рабочий контракт](../features/auth-settings.md#публичная-политика-в-работе--a62b-local).
- 14.4t. Тогда же protected integration settings/secrets API: SMTP/provider configuration и ввод/замена secrets, чтение только configured/masked state. Permissions + MFA/fresh auth, encryption/secret storage, version/conflict/validation, audit без payload, rotation и безопасные connection tests. Root encryption key и первоначальный admin требуют минимального внешнего operational setup.
- 14.4u. Последней функциональной задачей реализовать UI настроек поверх 14.4s/14.4t: выбор методов, обязательность email verification после password registration, SMTP/providers/secrets, отдельно роли и оплата. UI не заменяет backend enforcement. После завершения backend этапов 5–13; frontend stack выбрать перед работой. До этого работают нынешние operational env и политики, UI/динамические настройки не реализуем. Финальные copy/acceptance проверки и release 14.5 выполняются после этих задач.
- 14.4u-admin. В той же финальной UI-задаче добавить пользователей: создание/приглашение, поиск и bounded список, блокировка, роли и optional прямые permissions, просмотр effective access и отдельное управление manual grants. Платный доступ/срок/источник показывать отдельно от account status и административных прав. Платёжный раздел виден только в выбранном профиле; подтверждение оплаты берётся с backend, не из success redirect. Протестировать одинаковую защиту операций через UI и прямой API; отсутствие UI не блокирует backend provisioning/integration.
- 14.4u-setup. Финальный UI первого запуска поверх 10.3/13.1: мастер создания первого супер-админа после operator proof, пароль/контакт/MFA enrollment и завершение; после durable initialization только login. Не автозапускать setup на каждом boot и не разрешать browser-only обход. Проверить first install, concurrent tabs/instances, retry после сбоя и partial enrollment, restart и потерю/удаление admin без повторного открытия мастера.
- 14.4u-recovery. В финальном UI показать стандартное восстановление пароля супер-админа по почте и отдельный lost-factor flow 13.1; сохранить нейтральные ответы и backend enforcement. Аварийную CLI-процедуру 10.3-recovery описать и проверить в runbook без публичной кнопки обхода. Доступность SMTP/старой почты не подменять сбросом БД или постоянным env-паролем.
- 14.4u-roles. Финальный UI каталога собственных ролей из 10.5 и ручных назначений из 10.6: создание/редактирование роли, выбор зарегистрированных permissions, назначение/отзыв и просмотр effective access. Не дублировать backend правила; показать конфликт версии/запрет делегирования и защиту последнего супер-админа. Проверить custom role без правок кода назначения, UI/direct API parity и запрет подмены системной роли.
- 14.5. Подтверждение release checklist ниже и тег первой поддерживаемой версии; записать результаты/ограничения, а не только отметить наличие инструментов.

Готово: clean checkout стартует по документации, migrations/API/Swagger/security checks и staging smoke подтверждены, exact dependency versions зафиксированы, выбран release scope, tag соответствует поддерживаемым функциям. Дальнейшие schema changes после production идут отдельными миграциями.

## 4. Перенос из go-template

Исторические пути в матрице описывают go-template на зафиксированном commit; рабочие решения и файлы Auth перечислены в [template-adoption](../template-adoption.md). Матрица ниже исполняется целиком в этапе 1: инфраструктура 1.2, окружение 1.3, HTTP/Swagger 1.4, HTTP client 1.5, operations 1.6, документация 1.7. Старые номера в колонке обозначают подробные требования, а не перенос в будущих этапах. После 1.8 вместо исходников использовать рабочие файлы Auth и `docs/template-adoption.md`.

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

14 октября 2026, 13.1d.1–d.3-local: [сценарий потери всех MFA-факторов](mfa-recovery.md) получил opt-in HTTP/App/ENV/Swagger, CLI approve/cancel с отдельными DB grants/session_user/OID/audit и independent durable delivery. Замена только после current approval + primary/browser + нового TOTP, без session/status/role/password override. Default-off, runtime не owner/operator; отключение новых операций не прекращает committed notice delivery. Далее d.4 operational приёмка, внешнее включение зависит от утверждённой проверки владельца; UI ещё нет.

14 октября 2026, 10.3b-local: готова отдельная CLI смены пароля существующего super-admin через DB operator membership + точное подтверждение target/version. Сохранены роли/MFA/status/setup marker, атомарны revoke/cleanup/audit; обычный email reset проверен для admin. [Runbook](../features/admin-recovery.md). Внешняя операторская приёмка и lost-factor recovery ещё открыты; runtime HTTP bypass не добавлялся.

14 октября 2026, 10.3a-local: backend первого супер-администратора реализован — operator secret + email/TOTP proof, atomic account/system grant/audit/durable marker и две opt-in ручки. Общие Auth зависимости без новых workers; setup не выдаёт session и не открывается после потери admin. [Контракт](../features/initial-setup.md), проверки — [history](history.md). UI, аварийное recovery и внешняя приёмка пока открыты.

Этапы 0, 1 и 4 завершены. 5.1–5.4 и 5.5a–d реализованы и локально проверены: verification/recovery/session HTTP API/account status, opt-in email change/report/protected password recovery и необходимая часть SQL session security. 5.5e-local завершён, 5.6a deletion и 5.6b-worker реализованы и локально проверены; далее provisioning 5.7. Restore/ban-erasure 5.6b-operations открыты. Provenance — [template-adoption](../template-adoption.md); проверки и границы — ниже. Внешняя приёмка 5.5e-staging остаётся открытой: почта/browser и операционные процедуры ещё не проверены; auth/RBAC/MFA/billing release gates впереди, шаблон не готов к production release.

Проверка этого шага: `docker build -f deploy/Dockerfile.dev -t auth:devcheck .`; `AUTH_TEST_IMAGE=auth:devcheck AUTH_TEST_APP_ENV=dev AUTH_SMOKE_ONLY=true task check-integration` — exit 0. Проверены dev startup, migration up, runtime DB connection, PostgreSQL/Redis readiness, liveness, Swagger disabled (404), локальная SMTP отправка в Mailpit. Disposable project `auth-check-1791315226-3825` и его volumes удалены runner; существующая БД не затронута. Это не полный integration/backup drill или external SMTP delivery. На этапе 0 изменения были документационными; tests/lint/security scan и GitHub CI тогда повторно не запускались. Проверка local Markdown links и `git diff --check` прошла. Release checks этапа 14 сохраняются.

| Этап | Статус | Зависимость / результат |
| --- | --- | --- |
| 0. Архитектура и scope | Завершён 06.10.2026 | architecture, threat model и ADR 001–003; runtime реализация впереди |
| 1. Перенос и удаление reference | Перенос и cleanup завершены | Tests/lint и prod drill ранее; dev startup/SMTP smoke прошёл 06.10.2026 |
| 2. Инфраструктура | Выполнено в 1.2 | Durable audit sink — отдельно по ADR; здесь только контракт |
| 3. Toolchain/окружение/deps | Адаптировано в 1.3 | Dev startup/SMTP smoke после CGO fix подтверждён 06.10.2026 |
| 4. Структура/схема/API | Завершён | Дерево, SQL schema и API contract checks; security enforcement впереди |
| 5. Account lifecycle | 5.1–5.4, 5.5a–d, 5.5e-local, 5.6a/worker, 5.7a–b и 5.7c-local реализованы/проверены локально | Далее оставшиеся задачи 6; 5.6b-operations/5.5e-staging, protected admin/operator flow и non-password proof открыты |
| 6. Безопасность сессий | Частично выполнен, включая 6.1a/6.1b-local/6.4a/6.5-local/6.6/6.8a | SQL authority/atomic revoke, rotation/password fresh-auth, Origin/CORS/headers/optional TLS, registration race/retry contract, shared budgets/limits, indexed GC и CAS refresh локально проверены; MFA context, внешние SMTP/browser и mixed/multi-instance release приёмка впереди |
| 7. Identities / SSO boundary | Не начат | После 0, 4, 6; общий SSO optional |
| 8. Telegram/OIDC/OTP | Backend локально реализован | Telegram + Google OIDC и email OTP; external/browser/fault/load gates открыты, Mini Apps отложены |
| 9. Policy/linking | Не начат | После 7–8; admin API зависит от 10 и 13.1 |
| 10. Roles/permissions | A4.1/2-local, 10.5a-local и 10.3-local реализованы | Роли/назначения/delegation/version/audit, JSON-каталог/preview и защита последнего системного владельца при block/delete; MFA, runtime/UI импорт, управление системными назначениями/bootstrap/recovery и полный usable-admin guard остаются открыты |
| 11. Plans/entitlements | Не начат | После 10; manual grants и effective access без payment provider |
| 12. Payments | Не начат | После 11; local provider или optional external events adapter; Stars зависит от commerce profile |
| 13. MFA/cabinet | A5.2b–d-local реализованы | MFA login/management, opt-in email proof и контролируемая admin+owner первичная привязка external-only contact; App/ENV/HTTP/Swagger/SQL guards. Dynamic role policy, общий admin users/roles API, first-admin/lost-factor recovery, UI и release gates открыты |
| 14. Release/переносимость | Не начат | После обязательных модулей и checklist; документация ведётся по ходу |

Текущий порядок: 0, 1.1–1.8, 4, 5.1–5.4, 5.2r/5.2h завершены; 5.5a–d реализованы и 5.5e-local проверен, 5.6a/5.6b-worker проверены локально → 5.7 и остальное 6 → 7/8 → 9/10 → 11/12 → 14. 5.6b-operations/5.5e-staging остаются release gates. Разделы 2–3 и перенос 4.2–4.3 входят в первый этап. Решения этапа 0 принимаются до зависимых задач; 13.1 выполняется после 6 до production admin действий. После 1.8 используем только рабочий Auth и его документацию.

История выполненных этапов и результаты проверок — в [history.md](history.md). Это архив, не текущая инструкция к выполнению.

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
