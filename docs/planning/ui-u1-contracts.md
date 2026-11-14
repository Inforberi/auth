# U1: контракты двух режимов управления и порядок реализации

Дата: **14 ноября 2026**. Статус: **детализированный план, не реализованный API/установщик**. Основание — [U1–U7](ui-management.md), [инвентаризация backend](../admin-ui-specification.md), `.env.example` (185 параметров на дату сверки). Этот документ определяет целевое поведение; текущие seed-only настройки ещё не стали полноценным ENV-режимом. Код, UI, рабочие конфигурации и БД при детализации не меняются.

## 1. Конечный состав первого выпуска

Два режима одного backend: **ENV** без обязательной панели и **управляемый API** с нашей панелью, UI CRM или прямым клиентом. Режим выбирается для установки, не отдельным переключателем каждого проекта. Standalone/multi-project — независимая топология, не третий режим настройки.

В выпуск входят группы U2–U6: Auth/MFA, сроки и лимиты, frontend origins/страницы, пользователи/операторы, проекты и их lifecycle, роли/permissions, SMTP/Google/Telegram, JWT resources/consumers/keys, retention, backup/recovery, письма, собственный профиль и ограниченный audit/operation read. Используются существующие механизмы и транзакционные гарантии. Конкретные команды сгруппированы ниже; скрытого добавления интеграций/экранов сверх этого списка нет.

Не входят оплата/entitlements, общий пользовательский SSO, организации/multi-app, SMS/passkeys, генератор произвольных форм, собственный secret-manager продукт, новый брокер/оркестратор, автоматическая смена cloud DNS/сертификатов, перенос между PostgreSQL hosts и автоконфигурация внешних провайдеров. Не добавляем редактор SQL/DSN, произвольный URL-fetch или импорт непроверенного DB dump через браузер. Это не отменяет согласованные backup/restore и ротацию credentials в пределах доверенной инфраструктуры.

## 2. Источники настроек и рабочие данные

| Класс | ENV-режим | Управляемый API-режим | Кто меняет |
| --- | --- | --- | --- |
| P — прикладная политика | Явный ENV, иначе проверенный default | Feature-local settings в соответствующей БД | Администратор scope с нужным permission; в ENV read-only через HTTP |
| S — внешний credential | Защищённая startup-конфигурация/secret reference | Encrypted settings; write-only replace/clear | Разрешённый администратор; наружу только presence/version |
| G — внутренний ключ/credential | Владелец предоставляет защищённый материал; допустим явный install generate | Установщик/executor генерирует и сохраняет, далее защищённая ротация | Владелец установки либо явно ограниченный credential owner |
| C — каталог/структурированный файл | Существующий доверенный config manifest | Типизированные feature records, импорт только по контракту | Соответствующие Access/JWT/settings permissions |
| I — инфраструктура/потолок | Startup-конфигурация | Сохранённая конфигурация установки, формируемая установщиком | Эксплуатация/владелец; безопасные metadata в UI, изменение только отдельной операцией |
| B — bootstrap/identity | Установочные параметры/защищённая процедура | Сгенерированные или подтверждённые установочные значения | Установщик и независимый recovery, не обычная settings-форма |

Политики могут материализоваться в SQL и в ENV-режиме: текущие SQL guards/version/authority остаются источником истины для исполнения запроса. До публикации трафика доверенная startup-процедура валидирует выбранный ENV snapshot и согласованно применяет только принадлежащие ему настройки через владельцев фич. Не обходить service/domain/locks через прямой UPDATE. Это будущая доработка: нынешний Initialize игнорирует seed при наличии строки и сам по себе не реализует ENV ownership.

ENV resync явный: предыдущее/новое значение, источник, версия, аудит; no-op без записи. Несовместимое ужесточение/неподготовленный метод отклоняет запуск или оставляет scope закрытым, не ослабляет last-admin/factor guards. Разные значения или режимы на двух экземплярах одной установки запрещены: пока конфигурации не согласованы, новый экземпляр не ready. Старые writers при миграции исключаются maintenance-процедурой.

В API-режиме defaults применяются однократно. Ни startup ENV, ни restart не перезаписывают существующие настройки/keys. Потерянная обязательная строка, недоступный secret store или нерасшифровываемый credential — отказ, не first install и не fallback.

Пользователи, сессии, роли, назначения, собственные факторы и журнал — **рабочие данные**, не ENV-параметры. Они остаются в SQL и доступны разрешённым API в обоих режимах. C-каталог definitions/resources в ENV read-only через настройки, но обычные роли/назначения не превращаются в файл. MFA policy, не имеющая сегодня ENV, получает типизированный startup input в своей фиче при реализации; имена новых переменных/flags в U1 не выдумываем.

Управляемый источник возвращает effective source; I ceilings ограничивают P бюджеты в обоих режимах. Снятие прикладного лимита до нуля не отключает обязательную защиту. Никакого общего mutable key/value store, глобального config DTO или SQL/Redis чтения всей конфигурации на каждый запрос.

## 3. Области и полномочия

| Область | Данные | Контракт полномочий |
| --- | --- | --- |
| Установка | Режим, runtime resources, secret store, roots, технические backup/DDL операции | Владелец установки; отдельный executor; ни project admin, ни произвольный platform operator |
| Общая панель | Операторы, её Auth/MFA и журнал | Текущие platform session/permissions, last-owner/admin и свежесть proof |
| Defaults новых проектов | Копируемые профили без общих raw секретов | Владелец/явно уполномоченный оператор; существующие проекты не меняются |
| Проект | Пользователи, policies, permissions, providers, ключи/consumers проекта | Собственный project admin или текущая platform authority через проверенный bridge |
| Личный аккаунт | Own sessions, MFA, контакты и предпочтение | Владелец аккаунта; администратор не читает чужие secrets/codes |

Одна операторская сессия управляет разрешёнными проектами через платформенные команды, не impersonation и не project cookie. Project UUID/realm/binding берутся из доверенного server context; actor не выбирается JSON-полем. Owner-only определяется защищённой authority, а не строковым названием пользовательской роли. Привилегию нельзя выдать себе редактированием catalog definitions.

Не вводим обязательную MFA всем администраторам как новую глобальную политику: optional/administrators/required остаются выбором владельца. Но существующие чувствительные команды, требующие fresh password+MFA, не получают обход ради UI. Readiness объясняет, что именно нужно подключить/подтвердить. Изменение набора допустимых proofs — отдельный контракт фичи, не побочный эффект нового режима.

## 4. Установка без ручного ENV

### 4.1. Базовый поддержанный вариант

Первый управляемый вариант — один доверенный Docker Compose host и существующие PostgreSQL/Redis deployment patterns. Не добавлять зависимость на внешний vault. До реализации уточнить используемую host filesystem boundary по текущему deploy: базовый защищённый файловый комплект вне catalog DB, каталог только владельцу/executor, атомарная публикация файлов, read-only mounts runtime, отдельные writable полномочия executor. Файлы — не доказательство защиты от root хоста: такой доступ входит в доверенную инфраструктуру. Шифровать копию ключом, лежащим рядом, не считать off-host protection.

Для существующего внешнего PostgreSQL/Redis владелец передаёт адрес, TLS trust и ограниченные provisioning credentials через защищённый локальный файл/канал установщика. Не argv, shell history, URL страницы или логи. Без соответствующих прав установка не создаёт БД/роли и UI не обещает их смену. Домены/доверенный TLS и внешний storage остаются реальными ресурсами владельца, не сгенерированной фикцией.

### 4.2. Минимальный ввод и результат

| Ввод | Без ручного ENV | Если не предоставлен |
| --- | --- | --- |
| Режим и топология | Выбор ENV/API и standalone/multi-project в install command/wizard | Для нового управляемого варианта — API и закрытый профиль; существующая установка не меняет режим автоматически |
| Storage | Локальный managed PostgreSQL/Redis или защищённое внешнее подключение | Для managed host сгенерировать отдельные SQL/Redis credentials; внешний недоступный сервер не подменять локальным |
| Публичный origin/домены | Явное подтверждение владельца; локально loopback для разработки | Не публиковать production flow с localhost/self-signed defaults |
| TLS | Передать trust/cert/key или настроенную доверенную termination topology | Production listener не открывать; автоматический ACME не входит в выпуск |
| Recovery destination | Защищённое место хранения комплекта вне целевой БД, независимый доступ владельца | Не объявлять disaster recovery готовым; до выдачи установочной готовности подтвердить сохранение комплекта |
| Внешние интеграции | Ввод позже через API/UI | Отключены; SMTP-dependent сценарии не ready |
| Ресурсы | Проверенный bounded baseline + допустимые host overrides | Согласованные I ceilings, не автоматическое обещание RPS по RAM/CPU |

Установщик создаёт стабильный install/realm identity, roots/key IDs, раздельные owner/migration/runtime/reader credentials по существующим grants, а для включаемого JWT — signing material. Secrets генерируются до использования, фиксируются в защищённом store и проверяются. Включение JWT/внешнего метода не следует из наличия ключа. Пароль первого человека задаётся владельцем по защищённому setup, не общий сгенерированный пароль из README.

Первый setup: одноразовая установочная authority доставляется владельцу защищённым локальным способом, без публичного signup супер-администратора. Захват first-owner закрывается транзакционным marker. Повторный install использует существующий manifest/стадию, не генерирует новые roots и не снимает marker. Concurrent installers получают одного победителя. При неопределённом результате сначала читается receipt/сохранённая стадия, а не создаётся новый набор.

Readiness установки означает, что схема/grants/identity/обязательные secrets и источники настроек проверены. Project creation отдельно проходит подготовку/активацию; install ready не значит, что все методы входа готовы. Не открывать все APIs до готовности выбранного security profile.

## 5. Defaults и срок применения

Пример `.env.example` — dev input, **не production defaults**. Общие исходные значения первого managed выпуска:

| Группа | Начальное значение | Применение изменения |
| --- | --- | --- |
| Профиль | Закрытый сервис; пароль, публичная регистрация off. Сайт с регистрацией — явный выбор | Проверенная policy версия; запреты действуют в действующих сценариях по текущим guards |
| Email verification | У закрытого профиля disabled, без автопометки email verified; для сайта предлагается required после SMTP/страницы | Required без prerequisites не активируется; существующие права/credential constraints не обходятся |
| MFA | Личная политика optional; встроенный TOTP adapter доступен, требование роли/действия сохраняется; operator recovery не включается без отдельной authority | Строгие переходы/last-factor остаются у владельцев фич |
| Внешние методы, email OTP, email change/binding, invitations/temp, native/exchange | Off до явного включения и readiness | Не отзывать старые proofs только из-за UI-флага без контракта; где нужна invalidation — явная операция |
| Обычная session | idle 168h, absolute 336h; refresh threshold 24h | Новые выдачи/refresh по контракту, уже записанный absolute deadline не продлевать молча |
| Admin session | idle 30m, absolute 12h; activity interval 1m; fresh proof 5m | Ужесточение проверяется при authority read; более длинная настройка не продлевает старый абсолютный срок |
| MFA challenge / email OTP / binding | 5m; OTP resend 1m; email-factor preparation 3m/resend 1m | Уже выданные challenges сохраняют исходный expiry; final guards проверяют актуальную policy |
| Verification / password reset | verification 30m/resend 1m; reset 1h | Следующая выдача; explicit revoke — отдельная команда |
| Invitation / temp password | 24h, reissue cooldown 1m; restricted temp setup 10m | Новые выдачи; временный пароль не выдаёт полную session до завершения |
| Email change | confirm/recovery 30m, protection 24h | Не отменять действующую protective recovery повышением policy |
| JWT/refresh | access 2m; refresh idle 168h/absolute 336h; strict для чувствительных операций | JWT exp неизменяем; local revoke ограничен expiry/trust rotation, refresh по SQL authority |
| Retention | sessions 30d, audit 180d, email reservation 30d | Следующая bounded worker batch; shortening с подтверждением, не lifetime доступа |
| Access | 32 роли на пользователя; custom definitions/роли только явными действиями | Понижение лимита не снимает уже выданные роли автоматически |
| Backup | 24h, последние 7 успешных копий | Следующий запуск scheduler, protected delete; RPO/RTO отдельно, никакого обещания host DR из volume |
| Production diagnostics | log info, Swagger off; dev профиль явно отдельно | Rollout, без вывода raw secrets/токенов |
| SMTP и origins | Внешний SMTP unset; TLS обязателен в production, destinations только trusted; CORS off, origins задаются явным подтверждённым origin | SMTP со следующей отправки, CORS/browser policy по версии; SMTP test не доказательство доставки |

Standalone API `GET/POST /api/v1/admin/auth/settings/sessions` управляет сроком бездействия, абсолютным сроком и порогом продления обычных браузерных сессий, а также сроком бездействия, абсолютным сроком и интервалом записи активности административных сессий. Все значения в секундах. Сроки бездействия и абсолютные сроки ограничены конфигурацией запуска. В API-режиме новая политика применяется при выдаче (включая завершение MFA). Выданные сессии сохраняют записанные сроки и параметры продления; записи до миграции 000004 сохраняют абсолютный срок и используют прежние настройки продления. В ENV API возвращает эффективные настройки, изменение через него запрещено. Fresh proof, JWT, операторские и проектные сессии сохраняют собственную конфигурацию. Миграция 000004 применяется к standalone, версия и checksum автоматически подготавливаемой проектной схемы остаются прежними.

Для P budgets baseline — числовые значения из таблицы ENV ниже (за минуту, если имя/текущий контракт так определяет); это защита, не RPS/capacity. I ceilings — соответствующие current bounded examples после startup validation. Не брать dev usernames/passwords, sslmode=disable, localhost action URLs или SMTP mailpit в production. Если значение зависит от trust/credential/domain, отсутствие означает not configured, не скрытый рабочий secret. Все TTL/cooldown/input bounds сохраняют domain validators; уточнение допустимого диапазона в UI metadata не ослабляет существующий предел.

## 6. Контракты чтения, изменения и операций

Ниже **проектирование**, не утверждение, что новые routes/DTO уже есть. Существующие API/форматы сохраняются; их фичевые контракты приоритетны: [Auth](../features/auth-settings.md), [SMTP](../features/smtp-settings.md), [providers](../features/provider-settings.md), [retention](../features/retention-settings.md), [platform Auth](../features/platform-auth-settings.md). Не заменять их общим settings endpoint.

### 6.1. Общая семантика

- Read возвращает только разрешённый scope, текущую feature version, effective policy и безопасные metadata: source ENV/API/installation, readonly, bounds/units, readiness/reasons, момент применения. Это концептуальные поля; существующий response расширяется совместимо только по необходимости. Не читать все secret records ради формы. Локальная adapter readiness не считается fleet ready.
- Update новых settings groups — полная типизированная policy + expectedVersion; missing/unknown/null invalid, где поле не nullable. Старые conventions не ломаются. Текущие permission/proof/session/версии проверяются в транзакции с audit. No-op не обновляет version/audit. Conflict требует перечитывания и нового решения, не blind retry.
- ENV-owned update получает понятный read-only отказ **после** проверки авторизации; settings read не раскрывается публично. Не отключать management API пользователей/ролей из-за ENV policy ownership. Для новых groups планируется локальный код `settings_source_read_only` (409); существующие errors не переименовывать ради симметрии.
- Локальные settings, которым достаточно транзакции, возвращают 200 с committed version. Внешняя проверка/DDL/rotation/restore — 202 с operation ID, либо существующий синхронный контракт, если он достаточен. Accepted не означает «пароль сменён». External I/O не выполняется под SQL authority lock.
- Write-only secret action для нового контракта: keep/replace/clear; raw new value допустим только при replace, clear запрещён при зависимом включённом методе. Старые SMTP/provider null/omitted правила сохраняются адаптацией в transport, не дублированием pipeline. UI-маска никогда не пароль. Secret receipt/логи содержат ID/version/presence, не raw/ciphertext. Generated consumer secret выдаётся один раз; утраченный ответ требует защищённого перевыпуска, а не read старого секрета.
- Чтение/мутации — no-store, без implicit session refresh; действующие Origin/CSRF, JSON limits и browser/native separation сохраняются. CRM backend использует поддержанную administrative authority, а не произвольный Bearer JWT от пользователя вместо admin session. Новая machine-admin auth не входит в U1.
- Существующие 400/401/403/409/429/503 и фичевые mapper сохраняются. Для новых groups отдельно фиксируются invalid policy, version conflict, readonly source, not ready, confirmation required; безопасная диагностика без DSN/keys. Dependency failure не превращать в success или повтор seed.

### 6.2. Группы команд и владельцы

Имена новых групп ниже — контракт ответственности, не готовые URL. Конкретные маршруты добавляются в transport владельца и OpenAPI в соответствующем блоке, с существующими `/api/v1/admin/...` и `/api/v1/platform/projects/{id}/...` conventions. Не занимать фальшивые routes/заглушки до реализации.

| Группа | Read / команды | Scope / owner | Реализация |
| --- | --- | --- | --- |
| Источник/metadata | Mode, policy versions, readiness/reasons, read-only bounds | Startup + safe local/platform settings views | U2; mode не меняется обычным POST settings |
| Auth/MFA | Existing policy read/update; публичный минимальный effective-method discovery без account details | `auth/settings`, platform/project bridge | U2/U3; переиспользовать существующие policy/guards |
| Session/timing | Read/update session/admin/fresh-proof/OTP/verification/invitation/temp timings | Владельцы session/method/account settings, не один огромный DTO | U2 |
| Budgets/frontend | Read/update logical quotas, trusted frontend origins/action URLs | Фичевые domain/service, transport и installation ceilings | U2; не произвольные callbacks/issuer URLs |
| Users/operators | List/read/create/invite/temp/status/delete/bind email, protected admin assignment | Account/provisioning, administrators, platform bridges | U3; last-owner/last-admin и current authVersion |
| Projects | Preview/create/prepare/result/activate/suspend/resume, metadata, owner-only delete | `admin/projects` services + trusted preparation executor | U3; current project version/generation, binding immutable |
| Backup/recovery | List/inspect/create/verify/download/delete/schedule; preview/confirm/restore/result | Backup executor и scope authority | U3.1; opaque IDs, no raw paths/SQL; platform restore независим от target DB |
| Definitions/roles | CRUD definitions, custom role edit/archive, assignment и effective access | `access` и project/platform adapters | U4; built-in security permissions защищены |
| SMTP/providers/bot | Existing read/update/test + platform bridge | `auth/settings` и integrations | U3/U5; внешние secrets вводит владелец |
| JWT | Resource/audience definitions, consumers create/rotate/disable, key metadata/generate/rotate | `auth/token` + credentials owners | U5; private key GET нет, fixed issuers/SSRF guards |
| Installation secrets/DB credentials | Metadata/rotation plan/execute/result, readiness, recovery export procedure | Ограниченный executor, ownership + infrastructure grants | U5; не SQL superuser в обычном API |
| Letters/self/audit | Draft/preview/test/publish/reset/rollback, own profile/security, paged redacted audit/results | Delivery/templates/account/audit owners | U6; одно render path, synthetic preview |

Platform bridge не подставляет local actor. Сохраняются operationId/expectedVersion/expectedGeneration/expectedPolicyVersion/reason там, где такой current contract уже существует. New mutations используют соответствующие project/policy/auth/access revisions по их владельцу, не одну универсальную глобальную version. Read-own receipts не становится read-any для всех операторов.

### 6.3. Контракт операции с внешними эффектами

До destructive действия: current authority, свежий proof по контракту, expected revisions, preview с точным scope/последствиями, ограниченный confirmation intent и operationId. Подтверждение связано с actor/scope/version/action и истекает; ответ не содержит proof/секреты в URL. Повтор operationId с тем же intent читает имеющийся результат; с другим payload — conflict. Не хранить raw secret в idempotency payload/audit для сравнения.

Операция сохраняет стадию до внешнего эффекта; затем preflight → prepare → verify → switch → retire → completed. Для конкретного действия лишние стадии не создавать. При сбое — явный failed/recovery-required/ожидание согласованного rollout, receipt и допустимое действие, без бесконечного автоматического retry. Процесс может продолжиться после потери HTTP-ответа или restart без повторного DROP/неучтённой выдачи credentials. Нет общей ACID-транзакции между PG ALTER ROLE, файлами и всеми API replicas.

Исполнитель переиспользует existing CLI/preparation/intent/receipt механизмы с bounded concurrency; сеть/DDL отдельно от обычного request runtime. Новая постоянно работающая очередь/брокер не нужны. У длительной операции есть timeout/cancel semantics; отмена после необратимого эффекта не означает rollback. Закрытие ресурсов и подтверждение актуальности catalog защищают от выполнения по старой binding.

## 7. Secrets, ротация и независимый recovery

| Материал | Создание/хранение | Замена и recovery |
| --- | --- | --- |
| Root project/account encryption | CSPRNG, стабильный key ID, защищённый store вне зависимой DB; backup отдельно | Re-encrypt по версиям/parties, проверка чтения, old-key retention до обработки зависимых backups; не JSON-поле обычной формы |
| Project DB runtime credential | Managed preparation с ограниченной role, encrypted catalog record с project binding | Новый credential/role в допустимых grants, verified connection, обновление revision и drain old pools; не raw owner DSN |
| Catalog runtime/reader/migration/owner | Раздельные credentials и выдача только нужному компоненту | Владелец установки, explicit rollout, независимый recovery authority при недоступном catalog |
| Redis credential | Сгенерирован для managed Redis либо предоставлен для внешнего | Обновить поддержанным server-side ACL/credential workflow и consumers; формат сервера/права проверить до реализации, без обещания двух паролей всегда |
| JWT signing/JWKS | Generate по поддержанному алгоритму, private readonly store, public metadata | Active/retiring windows; planned rotation и emergency distrust различаются; local tokens до exp требуют отдельного trust решения |
| SMTP/Google/Telegram bot/client | Внешний ввод, scoped encrypted settings | Replace/test/readiness, pending flows учитывают revision; внешний credential сам по себе не отзывается записью в нашей БД |
| Initial setup/recovery token | Одноразовый защищённый канал/файл с коротким действием | Не восстанавливать публичный setup marker; recovery не master-password и не автоматическое снятие MFA |
| Consumer secret | Generate, verifier в storage, once-only output | Rotate с bounded overlap/disable; утраченный ответ — перевыпуск, не GET raw secret |

Root/DB rotation через UI доступна только в API-режиме и при доступном исполнителе/полномочиях. Для ENV тот же безопасный эксплуатационный workflow применяется вне обычного settings API с явным обновлением конфигурации. Ни один secret не обязан становиться browser-readable ради управляемости.

Для PostgreSQL не обещать overlap сменой password одной role: первый выпуск допускает явно подтверждённое maintenance window; при безопасно поддержанной сменной identity использовать её, сохраняя current ownership/grants. Новую identity удалять только после завершения старых leases/connections, не раздавать ей лишних прав. Plan показывает downtime/rollout before confirm. При compromise не возвращать утёкший key для «успешного rollback».

Recovery pack: versioned manifest с install/realm/binding/schema/app versions и ссылками на защищённые backups, необходимые key versions и trusted storage config. Raw root material — только отдельно защищённый файл/secret reference, не общий JSON export UI. Комплект не хранится только на том же volume/в той же БД; владелец подтверждает независимое сохранение. Скачивание через браузер допускается только для специально защищённого export без смешения с обычным metadata GET; базовый recovery корней — локальная процедура владельца.

Recovery без панели выполняется локальным отдельным tool/существующим CLI workflow с ограниченной authority и минимальным журналом вне целевой DB. Проверяет identity/backup/key binding, schema/grants, приводит credentials/authority к актуальному состоянию и только затем допускает запуск. Ни потеря БД, ни недоступный key store не создают нового владельца автоматически. Secret rotation не доказывает восстановимость: перед retire old root нужно проверить recoverability требуемых копий.

## 8. Переход между режимами и upgrade

Для существующей установки **нет автоматического переключения**. Новый mode/config schema вводится совместимой миграцией и явной install adoption-процедурой. В ней проверяются текущая схема, scoped data, возможности всех instances, inventory secrets и backup; до согласованного cutover старые writers закрыты. Перезапуск не reseed и не повторный first setup.

ENV → API: preview текущего effective snapshot/источников без raw secrets, одноразовое сохранение через feature owners, проверка secret references/versions, фиксирование режима/версии, coordinated restart/rollout. Неподдержанный input блокирует переход, не теряется молча. API → ENV: явный maintenance export несекретной политики и отдельных protected secret references, проверка репрезентируемости всего включённого scope и принятие владельцем, затем cutover. Если существующий ENV/config формат не выражает нужную настройку, переход не разрешается до добавления типизированного support; сброс defaults вместо неё запрещён.

Переходы и rollback не меняют user UUID/roles/session ownership, не удаляют личные factors/keys и не выполняют reset БД. Строгие security changes могут потребовать явного отзыва/нового входа: это последствия конкретной policy, которые показываются в preview. Уточнить supported source versions в migration code соответствующего блока, не обещать upgrade любого старого dump.

## 9. Экран → данные → команда → последствия → ограничения

| Экран нашего UI или CRM | Read | Команда | Последствия / ограничения |
| --- | --- | --- | --- |
| Установка/состояние | Mode, stage, prerequisites, masked target IDs | Protected install/adopt/recover | Root authority только до/вне обычного HTTP; не публичный первый админ |
| Проекты | Directory/state/readiness/results | Prepare/activate/suspend/delete | Отдельная БД на проект, owner-only destructive, никакого SSO |
| Вход/безопасность | Effective policy/source/versions | Existing policy + session/timing/budgets update | ENV-owned readonly, readiness/last-admin, scope ceilings |
| Пользователи/операторы | Paged list/detail/roles/status | Invite/temp/status/delete/assignment | Actor current authority, last-admin/owner, необратимые действия подтверждаются |
| Роли/permissions | Catalog/role/effective access | Definitions/role/assignment commands | Внешний backend сам enforce field/record permissions; built-ins защищены |
| Интеграции | Safe config, secret presence, tested version | Keep/replace/clear/test | SSRF allowlists, test не delivery; неизменяемые issuer endpoints |
| JWT | Resources/consumer/key metadata | Create/rotate/disable/update | Secret once-only, exp/JWKS trust limits, audience allowlists |
| Keys/DB credentials | Inventory, active versions, operation status | Protected plan/confirm/rotate | Executor grants; не raw keys/DSN редактор; recovery при частичном успехе |
| Backup/restore | Copy IDs/composition/verify/result | Create/verify/schedule/download/delete/restore | DB+keys+roles нужны вместе, без arbitrary dump/SQL, platform restore с независимым status |
| Письма/профиль/audit | Templates/self/security/redacted journal | Publish/test/reset/own security commands | Synthetic isolated preview; собственные secrets/codes не общие editable поля |

## 10. Порядок реализации без повторного переписывания

| Шаг | Законченное изменение | Зависимость / приёмка |
| --- | --- | --- |
| 1. U2 foundation | Typed mode/source contract, feature-local adapters, defaults и feature metadata; ENV synchronization/managed persistence без новых frameworks | Catalog migration/source ownership до новых writers; только affected modes/settings tests |
| 2. Install foundation U3/U5 | Защищённый local manifest/secret store, idempotent install/adopt, отдельные credentials, setup/recovery boundary | Сначала storage of roots и recovery authority, затем выдача privileged commands; не browser installer с пустой защитой |
| 3. U2 policies | Session/TTL/limits/frontend/discovery и source-readonly enforcement | До реализации форм; обе mode ветки, policy versions, no fallback, bounded refresh |
| 4. U3 management | Недостающие user/operator/settings bridges, project preparation/lifecycle/delete | Existing domain/service/transactions; current project state и own receipts |
| 5. U4 access | Managed definitions/import, role update/archive и effective read | Существующие assignment/last-admin safeguards, без импорта автоматических grants |
| 6. U5 credentials/JWT | SMTP/provider bridges, resources/consumers, signing/root/DB rotation с устойчивыми receipts | Install/executor foundation шага 2 уже готова; только затронутые failure/restart/rotation paths |
| 7. U3.1 recovery | Backup каталог/scheduler/verify, безопасный download/delete и guarded restore, независимый recovery CLI | Secrets/operation lifecycle согласован, ключи/ACL включены в recovery contract; не писать второй restore pipeline |
| 8. U6 | Templates/self/audit/минимальная диагностика | Не менять auth pipelines ради screens, bounded reads без dashboard full scans |
| 9. U7 + README | Приёмка только новых cross-feature/mode contracts, actual examples/install/readme, спецификация API/UI | Reuse валидных PASS; сначала согласование макета/стека, потом отдельное разрешение на frontend |

U1 уточняет зависимости U2–U7: installation/secret foundation выполняется до использующих его U3/U5 операций, backup management после готовности recovery authority. Номера U — области, не требование сначала дописать всю U3.1 без ключей. Не создавать на этих шагах frontend-заглушки. Каждый шаг передаётся Luna законченным delta; после ошибки повторяется affected проверка, а не все прежние suites.

## 11. Что считается завершением U1

Контракт U1 детализирован этим документом и полной таблицей ниже: source/scope/owner/default/application определены; установочный/recovery baseline и существующие API отличены от будущих. Окончание планирования не означает готовность режимов/установщика/ротации или закрытие [эксплуатационных ограничений](../operations/operational-security-2026-11-13.md).

Перед началом кода требуется выбор пользователем следующего рабочего блока; новые прямые зависимости и конкретный внешний secret manager потребуют отдельного разрешения. Никакого разрешения на UI этот план не даёт.

## 12. Матрица всех текущих ENV-параметров

Таблица перечисляет каждый из 185 ключей `.env.example` один раз. **Пример** — значение текущего dev template, не утверждение о production default; защищённые значения скрыты. Целевые initial defaults см. раздел 5, остальные числовые quotas/TTL используют приведённый baseline после feature validation. Deployment topology/trust values получают подтверждённые install значения; пустые credentials не допускают включение зависимого метода.

В ENV источник — этот ключ/защищённая ссылка и startup rules раздела 2. В API — источник по классу P/S/G/C/I/B. Колонка **Группа** задаёт scope/владельца/применение через легенду после таблицы. File/DSN поля — существующий вход, не форма для raw path/DSN в UI. Имена новых mode/policy полей не вводятся этой таблицей. Ключ `EMAIL_OUTBOX_KEY` остаётся существующим input к scoped encryption: не дублировать его новым независимым root только из-за исторического имени.

| ENV | Класс | Группа | Пример (dev) |
| --- | --- | --- | --- |
| `APP_NAME` | I | Установка | `auth-dev` |
| `APP_ENV` | I | Установка | `dev` |
| `PLATFORM_ENABLED` | I | Установка | `false` |
| `PLATFORM_REALM_ID` | B | Bootstrap | не задано |
| `PLATFORM_ORIGIN` | I | Установка | не задано |
| `PLATFORM_PROJECT_AUTH_DOMAIN` | I | Установка | не задано |
| `PLATFORM_STORAGE_TARGET` | I | Установка | `primary` |
| `PLATFORM_API_INSTANCES` | I | Ресурсы | `1` |
| `PLATFORM_SQL_CONNECTION_BUDGET` | I | Ресурсы | `80` |
| `PLATFORM_SQL_EXTERNAL_RESERVE` | I | Ресурсы | `4` |
| `PLATFORM_OPERATIONS_MAX_IN_FLIGHT` | I | Ресурсы | `8` |
| `PLATFORM_OPERATIONS_ACTOR_MAX_IN_FLIGHT` | I | Ресурсы | `2` |
| `PLATFORM_OPERATIONS_PROJECT_MAX_IN_FLIGHT` | I | Ресурсы | `2` |
| `PLATFORM_OPERATIONS_GLOBAL_PER_MINUTE` | P | Лимиты панели | `600` |
| `PLATFORM_OPERATIONS_ACTOR_PER_MINUTE` | P | Лимиты панели | `120` |
| `PLATFORM_OPERATIONS_PROJECT_PER_MINUTE` | P | Лимиты панели | `120` |
| `PLATFORM_PROJECT_HTTP_ENABLED` | I | Установка | `false` |
| `PLATFORM_PROJECT_AUTH_CONFIG_FILE` | C | Каталоги | не задано |
| `PLATFORM_PROJECT_HTTP_MAX_PROFILES` | I | Ресурсы | `8` |
| `PLATFORM_PROJECT_HTTP_MAX_BUILDING` | I | Ресурсы | `2` |
| `PLATFORM_PROJECT_HTTP_BUILD_TIMEOUT` | I | Ресурсы | `5s` |
| `PLATFORM_PROJECT_HTTP_PROFILE_MAX_AGE` | I | Ресурсы | `30s` |
| `PLATFORM_PROJECT_HTTP_MAX_IN_FLIGHT` | I | Ресурсы | `32` |
| `PLATFORM_PROJECT_RUNTIME_ENABLED` | I | Установка | `false` |
| `PLATFORM_RUNTIME_CATALOG_URL` | G | DB credentials | защищённое значение / ссылка |
| `PLATFORM_PROJECT_MASTER_KEY` | G | Root keys | защищённое значение / ссылка |
| `PLATFORM_PROJECT_MASTER_KEY_ID` | G | Root keys | не задано |
| `PLATFORM_STORAGE_HOST` | I | Установка | не задано |
| `PLATFORM_STORAGE_PORT` | I | Установка | `5432` |
| `PLATFORM_STORAGE_CA_FILE` | I | Установка | не задано |
| `PLATFORM_PROJECT_MAX_RUNTIMES` | I | Ресурсы | `8` |
| `PLATFORM_PROJECT_MAX_CONNECTIONS` | I | Ресурсы | `4` |
| `PLATFORM_PROJECT_SQL_BUDGET` | I | Ресурсы | `32` |
| `PLATFORM_PROJECT_MAX_ACQUIRING` | I | Ресурсы | `64` |
| `PLATFORM_PROJECT_ACQUIRE_TIMEOUT` | I | Ресурсы | `2s` |
| `PLATFORM_PROJECT_OPEN_TIMEOUT` | I | Ресурсы | `2s` |
| `PLATFORM_PROJECT_IDLE_TIMEOUT` | I | Ресурсы | `5m` |
| `PLATFORM_PROJECT_SYNC_INTERVAL` | I | Ресурсы | `5s` |
| `PLATFORM_PROJECT_SYNC_TIMEOUT` | I | Ресурсы | `2s` |
| `PLATFORM_PROJECT_DELIVERY_ENABLED` | I | Установка | `false` |
| `PLATFORM_PROJECT_DELIVERY_PARALLELISM` | I | Ресурсы | `2` |
| `PLATFORM_PROJECT_DELIVERY_PAGE_SIZE` | I | Ресурсы | `16` |
| `PLATFORM_PROJECT_DELIVERY_INTERVAL` | I | Ресурсы | `5s` |
| `PLATFORM_PROJECT_DELIVERY_FLEET_CONCURRENCY` | I | Ресурсы | `8` |
| `PLATFORM_PROJECT_DELIVERY_SMTP_ALLOWED_TARGETS` | I | Установка | не задано |
| `ACCESS_CATALOG_FILE` | C | Каталоги | не задано |
| `MFA_ENABLED` | I | Capabilities | `false` |
| `MFA_RECOVERY_ENABLED` | I | Capabilities | `false` |
| `MFA_ISSUER` | P | MFA | `Auth` |
| `MFA_LOGIN_CHALLENGE_TTL` | P | Сроки процессов | `5m` |
| `MFA_USER_OPERATIONS_PER_MINUTE` | P | Лимиты | `5` |
| `MFA_IP_OPERATIONS_PER_MINUTE` | P | Лимиты | `10` |
| `MFA_PROJECT_OPERATIONS_PER_MINUTE` | P | Лимиты | `500` |
| `PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_TTL` | P | Сроки процессов | `3m` |
| `PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_RESEND_INTERVAL` | P | Сроки процессов | `1m` |
| `PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE` | P | Лимиты | `100` |
| `PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE` | P | Лимиты | `1000` |
| `PLATFORM_PROJECT_EMAIL_MFA_USER_CHANGES_PER_MINUTE` | P | Лимиты | `5` |
| `PLATFORM_PROJECT_EMAIL_MFA_PROJECT_CHANGES_PER_MINUTE` | P | Лимиты | `500` |
| `PORT` | I | Установка | `8080` |
| `HTTP_TLS_CERT_FILE` | I | Установка | не задано |
| `HTTP_TLS_KEY_FILE` | I | Установка | не задано |
| `AUTH_CORS_ENABLED` | P | Frontend | `false` |
| `HTTP_MAX_IN_FLIGHT` | I | Ресурсы | `128` |
| `HTTP_REQUEST_TIMEOUT` | I | Ресурсы | `10s` |
| `HTTP_TRUSTED_PROXY_CIDRS` | I | Установка | не задано |
| `PASSWORD_HASH_CONCURRENCY` | I | Ресурсы | `2` |
| `LOGIN_IP_LIMIT` | P | Лимиты | `30` |
| `LOGIN_EMAIL_LIMIT` | P | Лимиты | `10` |
| `LOGIN_GLOBAL_LIMIT` | P | Лимиты | `1000` |
| `TELEGRAM_LOGIN_ENABLED` | P | Auth policy | `false` |
| `TELEGRAM_REGISTRATION_ENABLED` | P | Auth policy | `false` |
| `TELEGRAM_OIDC_CLIENT_ID` | S | Интеграции | не задано |
| `TELEGRAM_OIDC_CLIENT_SECRET` | S | Интеграции | защищённое значение / ссылка |
| `TELEGRAM_OIDC_REDIRECT_URI` | P | Provider callback | `https://localhost:8443/api/v1/auth/telegram/callback` |
| `TELEGRAM_LOGIN_IP_LIMIT` | P | Лимиты | `30` |
| `TELEGRAM_LOGIN_GLOBAL_LIMIT` | P | Лимиты | `1000` |
| `GOOGLE_LOGIN_ENABLED` | P | Auth policy | `false` |
| `GOOGLE_REGISTRATION_ENABLED` | P | Auth policy | `false` |
| `GOOGLE_OIDC_CLIENT_ID` | S | Интеграции | не задано |
| `GOOGLE_OIDC_CLIENT_SECRET` | S | Интеграции | защищённое значение / ссылка |
| `GOOGLE_OIDC_REDIRECT_URI` | P | Provider callback | `https://localhost:8443/api/v1/auth/google/callback` |
| `GOOGLE_LOGIN_IP_ATTEMPTS_PER_MINUTE` | P | Лимиты | `30` |
| `GOOGLE_LOGIN_PROJECT_ATTEMPTS_PER_MINUTE` | P | Лимиты | `1000` |
| `EMAIL_OTP_ENABLED` | P | Auth policy | `false` |
| `EMAIL_REAUTHENTICATION_ENABLED` | P | Auth policy | `false` |
| `EMAIL_BINDING_ENABLED` | P | Auth policy | `false` |
| `EMAIL_BINDING_TTL` | P | Сроки процессов | `5m` |
| `EMAIL_BINDING_REQUESTS_PER_MINUTE` | P | Лимиты | `100` |
| `EMAIL_BINDING_CONFIRMATIONS_PER_MINUTE` | P | Лимиты | `1000` |
| `EMAIL_OTP_TTL` | P | Сроки процессов | `5m` |
| `EMAIL_OTP_RESEND_INTERVAL` | P | Сроки процессов | `1m` |
| `EMAIL_OTP_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE` | P | Лимиты | `100` |
| `EMAIL_OTP_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE` | P | Лимиты | `1000` |
| `REGISTER_IP_LIMIT` | P | Лимиты | `5` |
| `REGISTER_GLOBAL_LIMIT` | P | Лимиты | `100` |
| `PASSWORD_RESET_GLOBAL_LIMIT` | P | Лимиты | `100` |
| `LOG_LEVEL` | I | Установка | `debug` |
| `SWAGGER_ENABLED` | I | Swagger | `true` |
| `SWAGGER_USERNAME` | I | Swagger | `swagger` |
| `SWAGGER_PASSWORD` | I | Swagger | защищённое значение / ссылка |
| `POSTGRES_IMAGE` | I | Установка | `postgres:18.6-bookworm` |
| `POSTGRES_DB` | I | Установка | `auth` |
| `POSTGRES_USER` | I | Установка | `auth` |
| `POSTGRES_PASSWORD` | G | DB credentials | защищённое значение / ссылка |
| `POSTGRES_PORT` | I | Установка | `5432` |
| `INITIAL_SETUP_ENABLED` | B | Bootstrap | `false` |
| `INITIAL_SETUP_SECRET` | B | Bootstrap | защищённое значение / ссылка |
| `DATABASE_URL` | G | DB credentials | защищённое значение / ссылка |
| `MIGRATION_DATABASE_URL` | G | DB credentials | защищённое значение / ссылка |
| `MAX_CONNS` | I | Ресурсы | `10` |
| `MIN_CONNS` | I | Ресурсы | `2` |
| `MAX_CONN_LIFETIME` | I | Ресурсы | `10m` |
| `MAX_CONN_IDLE_TIME` | I | Ресурсы | `5m` |
| `REDIS_HOST` | I | Установка | `redis` |
| `REDIS_PORT` | I | Установка | `6379` |
| `REDIS_PASSWORD` | G | DB credentials | защищённое значение / ссылка |
| `SESSION_TTL` | P | Sessions | `168h` |
| `ABSOLUTE_SESSION_TTL` | P | Sessions | `336h` |
| `SESSION_REFRESH_THRESHOLD` | P | Sessions | `24h` |
| `ADMIN_SESSION_IDLE_TIMEOUT` | P | Sessions | `30m` |
| `ADMIN_SESSION_ABSOLUTE_TTL` | P | Sessions | `12h` |
| `ADMIN_SESSION_ACTIVITY_INTERVAL` | I | Ресурсы | `1m` |
| `SESSION_FRESH_AUTH_TTL` | P | Sessions | `5m` |
| `AUTH_ALLOWED_ORIGINS` | P | Frontend | `https://localhost:8443` |
| `JWT_ENABLED` | I | Capabilities | `false` |
| `JWT_ISSUER` | P | JWT policy | `https://localhost:8443` |
| `JWT_SIGNING_KEY_ID` | G | JWT keys | не задано |
| `JWT_PRIVATE_KEY_FILE` | G | JWT keys | не задано |
| `JWT_KEYSET_FILE` | G | JWT keys | не задано |
| `JWT_RESOURCE_CONFIG_FILE` | C | Каталоги | не задано |
| `JWT_INTROSPECTION_CLIENT_CONFIG_FILE` | C | Каталоги | не задано |
| `JWT_INTROSPECTION_CONSUMER_LIMIT_PER_MINUTE` | P | Лимиты | `60000` |
| `JWT_INTROSPECTION_PROJECT_LIMIT_PER_MINUTE` | P | Лимиты | `60000` |
| `JWT_ACCESS_TTL` | P | JWT policy | `2m` |
| `JWT_NATIVE_ENABLED` | P | Auth policy | `false` |
| `JWT_REFRESH_IDLE_TTL` | P | JWT policy | `168h` |
| `JWT_REFRESH_ABSOLUTE_TTL` | P | JWT policy | `336h` |
| `JWT_ISSUANCE_ACTOR_LIMIT_PER_MINUTE` | P | Лимиты | `30` |
| `JWT_ISSUANCE_SESSION_LIMIT_PER_MINUTE` | P | Лимиты | `10` |
| `JWT_ISSUANCE_IP_LIMIT_PER_MINUTE` | P | Лимиты | `30` |
| `JWT_ISSUANCE_PROJECT_LIMIT_PER_MINUTE` | P | Лимиты | `3000` |
| `ACCOUNT_EMAIL_RESERVATION_DAYS` | P | Retention | `30` |
| `SESSION_RETENTION_DAYS` | P | Retention | `30` |
| `SECURITY_AUDIT_RETENTION_DAYS` | P | Retention | `180` |
| `RETENTION_BATCH_SIZE` | I | Ресурсы | `100` |
| `RETENTION_INTERVAL` | I | Ресурсы | `1m` |
| `PASSWORD_RESET_TOKEN_TTL` | P | Сроки процессов | `1h` |
| `PASSWORD_RESET_URL` | P | Frontend | `https://localhost:8443/reset-password` |
| `EMAIL_VERIFICATION_URL` | P | Frontend | `https://localhost:8443/verify-email` |
| `EMAIL_VERIFICATION_TTL` | P | Сроки процессов | `30m` |
| `EMAIL_VERIFICATION_RESEND_INTERVAL` | P | Сроки процессов | `1m` |
| `EMAIL_CHANGE_ENABLED` | P | Auth policy | `false` |
| `INVITATIONS_ENABLED` | P | Auth policy | `false` |
| `INVITATION_URL` | P | Frontend | `https://localhost:8443/activate-account` |
| `INVITATION_TTL` | P | Сроки процессов | `24h` |
| `INVITATION_REISSUE_COOLDOWN` | P | Сроки процессов | `1m` |
| `INVITATION_ISSUE_ACTOR_ATTEMPTS_PER_MINUTE` | P | Лимиты | `30` |
| `INVITATION_ISSUE_PROJECT_ATTEMPTS_PER_MINUTE` | P | Лимиты | `100` |
| `ACTIVATION_GLOBAL_LIMIT` | P | Лимиты | `100` |
| `TEMPORARY_PASSWORD_ENABLED` | P | Auth policy | `false` |
| `TEMPORARY_PASSWORD_TTL` | P | Сроки процессов | `24h` |
| `TEMPORARY_PASSWORD_SETUP_TTL` | P | Сроки процессов | `10m` |
| `TEMPORARY_PASSWORD_REISSUE_COOLDOWN` | P | Сроки процессов | `1m` |
| `TEMPORARY_PASSWORD_ISSUE_ACTOR_ATTEMPTS_PER_MINUTE` | P | Лимиты | `30` |
| `TEMPORARY_PASSWORD_ISSUE_PROJECT_ATTEMPTS_PER_MINUTE` | P | Лимиты | `100` |
| `TEMPORARY_PASSWORD_SETUP_PROJECT_ATTEMPTS_PER_MINUTE` | P | Лимиты | `100` |
| `EMAIL_CHANGE_URL` | P | Frontend | `https://localhost:8443/change-email` |
| `EMAIL_CHANGE_REPORT_URL` | P | Frontend | `https://localhost:8443/protect-account` |
| `EMAIL_CHANGE_RECOVERY_URL` | P | Frontend | `https://localhost:8443/recover-account` |
| `EMAIL_CHANGE_RECOVERY_TTL` | P | Сроки процессов | `30m` |
| `EMAIL_CHANGE_TTL` | P | Сроки процессов | `30m` |
| `EMAIL_CHANGE_PROTECTION_TTL` | P | Сроки процессов | `24h` |
| `EMAIL_OUTBOX_KEY` | G | Root keys | защищённое значение / ссылка |
| `SMTP_REQUIRE_TLS` | S | Интеграции | `false` |
| `SMTP_HOST` | S | Интеграции | `mailpit` |
| `SMTP_PORT` | S | Интеграции | `1025` |
| `SMTP_USERNAME` | S | Интеграции | не задано |
| `SMTP_PASSWORD` | S | Интеграции | защищённое значение / ссылка |
| `SMTP_FROM` | S | Интеграции | `auth@example.com` |
| `SMTP_DOMAIN` | S | Интеграции | `example.com` |
| `SMTP_ALLOWED_TARGETS` | I | Установка | не задано |
| `BACKUP_INTERVAL` | P | Backup | `24h` |
| `BACKUP_RETENTION_COUNT` | P | Backup | `7` |
| `RESTORE_HEALTHCHECK_SQL` | I | Recovery | `SELECT count(*) FROM auth.users;` |

### 12.1. Scope, владелец и момент применения групп

| Группа | Scope / владелец | Применение |
| --- | --- | --- |
| Установка | Install owner, config/server/infra/preparation | Generated install manifest или эксплуатационный override; restart/rollout. Изменение DB host/domain/storage target не обычный settings POST |
| Ресурсы | Install owner, existing admission/runtime/worker owners | Startup validation, сумма по экземплярам; rollout, не per-request pool creation |
| Bootstrap | Install identity/setup owner | Realm UUID стабилен; setup credentials одноразовы, не редактируемый scope |
| Root keys | Install owner + credentials/secretbox executor | Versioned re-encryption/recovery operation, не restart с потерей старого ключа |
| DB credentials | Install owner + trusted provisioning executor | Свой server credential либо внешний input; проверка, смена versions, drain/restart, recovery |
| Каталоги | Access/JWT владельцы и project profile capabilities | API records по версии; ENV trusted manifest. Физические пути не editable UI |
| Capabilities | Install owner + соответствующий adapter | Установщик включает компонент после prerequisites; permission policy отдельно. Recovery grants не включаются bool-флагом |
| MFA | Realm/project settings service; свой realm панели отдельно | Следующие выдачи TOTP metadata, актуальная policy; существующие enrolled параметры не переписать вслепую |
| Сроки процессов | Проект/realm панели только для поддержанных flows; владельцы account/method/MFA | Следующая выдача, current policy/versions при final proof; исходные deadlines не продлевать |
| Лимиты | Проект/realm, фичевые limiter/settings owners | Версия при следующей операции; те же Redis namespaces/counters, без сброса при save; в пределах I ceilings |
| Лимиты панели | Platform realm, текущий owner/delegated operation authority | Следующая admission операция; выше общих ресурсов не поднять |
| Frontend | Проект/realm, settings/domain/HTTP owner | Проверенный HTTPS/same-site contract внутри install trust; change может требовать rollout/pending-flow invalidation |
| Auth policy | Проект/realm, auth settings; platform policy отдельно | Policy commit, readiness/final authority guards; personal factors не удаляются при выключении capability |
| Интеграции | Проект/realm, SMTP/providers/bot owners | Saved credential version; SMTP следующая отправка, provider pending flow version; TLS_REQUIRED в production не отключать как dev convenience |
| Provider callback | Проект, provider settings + deployment trust | Только trusted origin/canonical callback, provider console agreement и coordinated rollout; issuer/endpoints фиксированы |
| Swagger | Установка, config/router | По умолчанию production off; отдельный generated credential при включении, guarded infrastructure change/rollout |
| Sessions | Проект/realm, session settings | Выдача/refresh и текущий admin authority; old absolute expiry не продлевается молча |
| JWT policy | Проект/realm, token settings | Новая выдача/refresh, issuer change только protected migration с trust impact; local exp не редактируется задним числом |
| JWT keys | Проект/realm, signing + credentials owner | Generate/rotation, public JWKS metadata; private path UI не задаётся |
| Retention | Проект/realm, retention settings | Следующая worker batch; days не session TTL |
| Backup | Установка/выбранный DB scope, owner/backup executor | Следующий scheduler run; retention удаляет только разрешённые копии по protected policy |
| Recovery | Install/recovery owner | Reviewed fixed check в operational workflow; никакого UI arbitrary SQL input |

G/S-класс не означает, что любое поле секретно: key ID/client ID/SMTP host — разрешённые metadata, private values — write-only. SWAGGER_PASSWORD относится к I-группе доступа к инфраструктуре, но хранится как secret; setup token — B и тоже secret. В managed режиме C manifest capabilities и I component switches могут быть производными от подготовленного install/profile, а не полями произвольного редактора.

### 12.2. Настройки, которых нет отдельными строками в ENV

В эту матрицу не выдумываются отсутствующие параметры: full Auth/MFA policy, max roles 32, Telegram Bot API settings, templates, custom permission definitions, generated per-project credentials/keys, JSON resource/consumer fields и backup manifests описываются типизированными контрактами своих групп выше. При реализации ENV-режима недостающие startup inputs добавляются явно с документацией, guards и миграцией; текущие API-owned поля нельзя молча считать поддержанными ENV. Реквизиты внутри structured manifests наследуют source/scope группы C, но private material хранится отдельно, не в публичном каталоге.

Standalone API `GET/POST /api/v1/admin/auth/settings/link-lifetimes` управляет сроками ссылок подтверждения email и сброса пароля в секундах. Допустимы 60–3600 секунд. Срок подтверждения должен превышать интервал повторной отправки. В API-режиме настройка применяется при регистрации, повторной отправке подтверждения и запросе сброса. Выданные ссылки сохраняют записанный срок. В ENV API показывает настройки запуска в режиме чтения.

В standalone `GET/POST /api/v1/admin/auth/settings/credential-lifetimes` настраивает сроки MFA при входе, привязки email, приглашений, временных паролей и смены email. Параметр свежести пароля применяется к подтверждению пароля, привязке внешней учётной записи и смене email. Действующие ограничения административных операций проверяются отдельно. При изменении сроков выданные коды, ссылки и пароли сохраняют записанные даты окончания.

`GET/POST /api/v1/admin/auth/settings/login-budgets` управляет лимитами парольного входа на IP, учётную запись и установку в запросах за минуту. Значения ограничены настройками запуска. Сохранение политики сохраняет счётчики Redis.

`GET/POST /api/v1/admin/auth/settings/frontend` управляет активным списком origin из установки, CORS и адресами страниц подтверждения email и сброса пароля. Для новых адресов требуется HTTPS и origin из доверенного списка установки. Изменения лимитов входа и фронтенда подхватываются другими экземплярами после обновления кеша с интервалом до одной секунды. В ENV эти три API показывают настройки запуска и запрещают запись.

`GET/POST /api/v1/admin/auth/settings/operation-budgets` управляет квотами standalone для Google и Telegram OIDC, MFA, привязки email, приглашений и активации, временных паролей, выдачи JWT и introspection. Квоты заданы в операциях за минуту и ограничены настройками запуска. Параметры используются существующими счётчиками Redis. В ENV API показывает настройки запуска и запрещает запись. Системные лимиты безопасности, например число попыток ввода конкретного кода, задаются самим сценарием.
