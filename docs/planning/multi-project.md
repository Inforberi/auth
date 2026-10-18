# Независимые проекты с отдельными БД — до UI

Согласовано 18 октября 2026, порядок уточнён после локальных load/rest наблюдений: следующим выполняется `pre-ui-projects`, до A7/UI. Предельный RPS и длительные ресурсные прогоны перенесены в MP8, после реализации multi-project; отдельный исходный capacity больше не является условием начала MP1. Обычные tests/lint и targeted security/SQL/Redis проверки выполняются в каждом затронутом подэтапе, не откладываются до MP8. Текущий runtime остаётся однопроектным, этот документ — план, не результат реализации. Недоступные внешние проверки остаются NOT RUN и требуют явного решения об отсрочке, не считаются пройденными.

## Результат и границы

Один сервис и общий UI управляют независимыми проектами. У каждого проекта отдельная PostgreSQL-база с одинаковой схемой Auth, пользователями, ролями, настройками и сессиями. Общий каталог хранит идентификатор проекта, состояние подготовки, расположение и ссылку на защищённые credentials, но не объединяет пользователей проектов.

MP1 завершён как архитектурный этап: [ADR005](../adr/005-independent-projects.md) содержит проверенную карту владельцев зависимостей, routing/authority/browser границы и cutover. По отдельному ответу пользователя оператор управляет пользователями, ролями и настройками всех проектов из одной platform session. Это административный bridge с SQL guards/audit/receipt, а не project login/SSO и не автоматическое членство. Реализация MP2–MP8 открыта.

Отдельные БД могут сначала находиться на одном PostgreSQL-сервере и делить его ресурсы. Перенос проекта на другой сервер — отдельная управляемая операция, не обещание автоматической миграции. Код фич не копируется по проектам. Схемы `public/shop` вместо отдельных БД и несколько альтернативных способов хранения сейчас не реализуются.

SSO, регистрация нескольких приложений внутри проекта, организации и межпроектное объединение аккаунтов отложены. Сейчас не добавлять для них протоколы, таблицы, routes или пустые пакеты. Будущее SSO возможно внутри проекта; сам проект остаётся независимой областью безопасности.

## Карта этапов

- [x] MP1. Контракты и границы. 18 октября: [ADR005](../adr/005-independent-projects.md), targeted source audit владельцев SQL/Redis/hash/settings/keys/workers, точный origin binding, uncached catalog admission без default DB, одна platform session с отдельным admin bridge и план совместимого переноса. Runtime/SQL/ENV не менялись; не считать реализацией или проверкой multi-project.
- [ ] MP2. Каталог и административный доступ. Отделить оператора платформы от super-admin конкретного проекта: проектный администратор не создаёт соседние проекты и не видит их данные. Определить first-run оператора и безопасное назначение первого администратора проекта без общего пароля. Управление каталогом требует соответствующих прав, свежего MFA proof и аудита; project credentials никогда не возвращаются в API, Swagger или логи.
- [ ] MP3. Подготовка БД. Защищённый backend API создания проекта подготавливает отдельную БД/ограниченную runtime-роль, применяет версионируемые миграции и начальные настройки, затем переводит проект в ready. Привилегии создания БД не выдаются обычному Auth runtime; секреты шифруются/хранятся защищённо, корневой ключ вне каталога. Имена БД генерирует сервер, не интерполировать произвольное имя из UI в SQL. Повтор/конкурентный запрос не создаёт дубли; частичный отказ оставляет понятное состояние и допускает безопасное продолжение. Не делать автоматический DROP DATABASE при ошибке, не держать HTTP-запрос/транзакцию на всё время provisioning.
- [ ] MP4. Сборка и бюджеты. Использовать существующие фичи с зависимостями выбранного проекта, без копирования бизнес-логики и универсального DI framework. Ограничить число активных пулов, общий SQL connection budget по API instances/workers, время ожидания и закрытие простаивающих зависимостей; не открывать pool на каждый запрос и не держать безлимитный pool на каждый проект. Недоступность одной БД не должна переключать запрос на чужую. Задать fair admission и ограниченную конкуренцию фоновых задач, чтобы один проект не занимал все hash slots/SQL/worker ресурсы.
- [ ] MP5. Полная изоляция. Разделить Redis keys/flows/limits/idempotency, настройки SMTP/providers/secrets, outbox, audit и retention по проектам. Проверить callback/redirect/Origin/CORS/CSRF/browser cookie scope и browser-bound MFA/OIDC/email flows: путь/имя cookie сами по себе не являются границей доступа. Привязать сессии, JWT issuer/audience/key selection, JWKS/introspection consumer credentials и refresh к проекту; исключить acceptance чужого токена при совпавших UUID/kid. Политика немедленного отзыва и SQL authority сохраняется.
- [ ] MP6. Обновления и эксплуатация. Миграции каждой БД с версией, блокировкой конкурентного запуска, ограниченными партиями и явным состоянием ошибки; несовместимый проект не обслуживается молча старым кодом. Зафиксировать backup/restore/rotation/recovery и безопасную остановку одного проекта без остановки соседних. Перенос существующей установки оформить отдельно: сохранить пользователей/роли/настройки, определить инвалидирование старых сессий/токенов и переход URL/issuer, не сбрасывать рабочую БД. После SQL restore соблюдать прежние reconciliation/Redis-flow/key/fleet gates, а не только восстановить таблицы.
- [ ] MP7. Приёмка до UI. Два проекта с разными настройками/ролями/providers и одинаковыми email: независимые аккаунты. Негативные cross-project session/JWT/refresh/OTP/OIDC/MFA/admin/consumer/cache проверки, stale catalog/disable races, provisioning retries/partial failure и migration failure. Проверить права runtime и provisioning отдельно, SQL/Redis отказ одного проекта, отсутствие утечек секретов, работу cleanup и общий бюджет ресурсов на нескольких API instances. Старые однопроектные отчёты сохранить как baseline, не выдавать за приёмку новой архитектуры.
- [ ] MP8. Регрессия нагрузки. После MP1–MP7 повторить затронутые security/load-rest/memory/GC/cleanup проверки и итоговый pre-ui-capacity на многопроектной версии: число активных/простаивающих проектов, общий бюджет пулов/workers, noisy-neighbor и восстановление после перегрузки. Последний capacity-отчёт перед UI должен соответствовать фактическому коду/config. Результаты по отдельным проектам и всему стеку не смешивать; недоступные fleet/external проверки оставить открытыми.
- [ ] A7-projects. В составе UI: создать проект, показать состояние подготовки/ошибку и безопасный повтор, переключить проект, настроить его методы входа, пользователей, роли и secrets через готовый backend API. Разделить платформенные и проектные экраны/права. Не добавлять вторую реализацию правил во frontend; проверить прямой API и UI, в том числе запрет доступа к соседнему проекту.

## Целевая система

```text
Общая панель / Platform API
├── Платформенная БД: каталог, операторы, операции и аудит управления
├── Проект A → Auth API → PostgreSQL A
└── Проект B → Auth API → PostgreSQL B

Общий код Auth, ограниченные общие ресурсы, изолированные данные проектов
```

БД проекта хранит только данные Auth/access/settings/audit этого проекта. Это не автоматическое создание БД для произвольных бизнес-данных внешнего backend. Платформенная БД не становится общей таблицей пользователей всех проектов. Один email в двух проектах означает два независимых аккаунта.

Первые проектные БД можно создавать на одном заранее настроенном PostgreSQL-сервере. Это изоляция хранения/прав, не CPU/RAM/дисков/отказа сервера. Один Redis допустим при строгом namespace и общих бюджетах; физически отдельный Redis на проект и автоматическое создание серверов сейчас не требуются. Отказ общего каталога/Redis может затронуть несколько проектов — отдельная SQL-БД не означает полную независимость доступности.

## MP1. Архитектурные контракты до реализации

- [x] MP1.1. Карта владельцев SQL/Redis/hash/settings/OIDC/JWT/workers и process/project split — ADR005 §4; полный App.New нельзя создавать на каждый проект без разделения ресурсов.
- [x] MP1.2. ADR005 и multi-project дополнение threat model, включая privileged provisioning, admin bridge и cross-DB authority gap.
- [x] MP1.3. Immutable UUID/public DNS-safe slug отдельно от display name; rename не меняет storage/issuer/URL, входные значения не являются authority.
- [x] MP1.4. Отдельный exact auth origin и host-only cookie каждого проекта, отдельный platform origin; DNS/TLS operator-owned, без arbitrary custom domain automation.
- [x] MP1.5. Индексная authoritative catalog проверка до runtime lease; unknown/not-ready/suspended без fallback, backend dependency failure fail-closed. Положительный status cache в базовый профиль не входит; suspension не обещает rollback уже admitted операций/local JWT.
- [x] MP1.6. Сохранение feature contracts, source migration baseline000001, separate catalog/project compatibility contracts и maintenance/cutover с явным отзывом старых credentials — ADR005 §5–6. Номера будущих upgrades фиксируются при их реализации, не выдумываются сейчас; новая schema не считается совместимой без теста.

Готовность MP1: согласованный ADR, перечень владельцев/изменений, описание authority/browser границ и план переноса. Новые публичные flow не публикуются до реализации их защиты.

## MP2. Каталог и управление платформой

- [x] MP2.1-code. 18 октября: [основа каталога](../features/project-catalog.md) — отдельная migration platform.projects, domain states/identity/origin и read repository Read/Resolve/List с keyset bounds. Unit/task check lint0 PASS, текущий Auth не подключён к каталогу, публичных ручек нет.
- [ ] MP2.1-sql. Реальный PostgreSQL integration gate открыт: opt-in тест написан/скомпилирован, но Docker daemon недоступен и локального PostgreSQL нет. Up/down/constraints/indexes/PUBLIC ACL на сервере не выполнены, не отмечать PASS. До закрытия не объявлять MP2.1 целиком завершённым и не включать runtime/provisioning.

- [ ] MP2.1. Отдельный набор миграций каталога, не смешанный с одинаковыми миграциями проектных БД. Минимальные данные: ID/название/публичная привязка, желаемое состояние проекта, фактическая стадия подготовки, версия, schema compatibility, доверенный storage target и ссылка на защищённый credential. Не хранить произвольные DSN в публичной карточке.
- [ ] MP2.2. Различать создание, ошибку подготовки, готовность и приостановку проекта. Доступность SQL/Redis показывать отдельно: timeout не должен автоматически превращать ready проект в заново создаваемый. Исчерпывающее перечисление состояний и переходов оформить в ADR, не размазывать набор booleans по сервисам.
- [ ] MP2.3. Платформенный оператор имеет отдельную identity/session/security область и явные полномочия управления каталогом. Super-admin проекта остаётся только внутри своего проекта. Обычное членство/роль проекта не выдаёт platform rights; создание проекта не делает платформенного оператора автоматически обычным пользователем всех проектов.
- [ ] MP2.4. Переиспользовать существующие password/MFA/fresh-auth/recovery механизмы, а не писать второй стек аутентификации панели. Определить безопасный first-run платформенного владельца, одноразовость/конкурентный запуск и operator recovery без сброса БД; recovery не является публичным MFA bypass.
- [ ] MP2.5. List/detail/create/retry/suspend/resume защищены platform permissions, актуальной session authority и необходимыми fresh password/MFA proofs. Мутации — optimistic version, защита повторов и атомарный audit факта управляющего решения. Аудит шага provisioning не выдавать за распределённую транзакцию с внешней БД.
- [ ] MP2.6. Пагинация и ограниченные фильтры списка, безопасные status/error codes, без credentials/SQL error text/DSN. Секреты в карточке только как «настроен/версия», не как возвращаемый masked plaintext.
- [ ] MP2.7. Одна platform session управляет users/access/settings любого разрешённого проекта через явный typed admin bridge по ADR005 §3. Зафиксировать platform permissions/action mapping, SQL guard/lock ordering/deadline, audit actor origin и operation receipt. Не подменять project user и не публиковать bridge до SQL revoke/concurrency/lost-reply tests; частичная потеря финального platform update не означает rollback проектной мутации. Не менять обычную project actor authority.

Готовность MP2: каталог и защищённые platform API проверены независимо от UI; запрос от проектного администратора к ним отклоняется.

## MP3. Создание БД и подготовка проекта

- [ ] MP3.1. UI/API выбирает только заранее разрешённый storage target; пользовательское имя проекта не становится SQL identifier или сетевым адресом. Для первого выпуска достаточно одного target. Не принимать произвольный host/DSN через публичный API и не создавать универсальный cloud provisioner.
- [ ] MP3.2. Входной запрос создаёт запись намерения и возвращает состояние подготовки, а не ждёт создания БД внутри HTTP handler. Использовать минимальную сохраняемую операцию/существующий worker подход: bounded concurrency, deadlines, прогресс, ограниченные повторы и защита конкурентного исполнения. Не добавлять broker/очередь ради одного процесса, если достаточно каталога.
- [ ] MP3.3. Шаги: зарезервировать ID/сгенерировать технические имена → создать БД/роли → применить схему/grants → записать настройки и независимые ключи → проверить ограниченное подключение/совместимость → опубликовать ready. До ready доступ разрешён только предусмотренному onboarding, а не всем Auth endpoints.
- [ ] MP3.4. Разделить credentials обычного платформенного API, ограниченного проектного runtime, migrator и provisioning executor. Привилегированные действия исполняет отдельная роль/процесс; её credential не доступен коду обработки обычного login. Проверить default/PUBLIC grants и отсутствие доступа проектной роли к данным каталога/соседних БД; не использовать owner/superuser как runtime.
- [ ] MP3.5. Секреты подключения и проектные integration/signing secrets хранить защищённо; root key вне БД. Шифрование связывает ciphertext с проектом, назначением и версией, чтобы перенос encrypted значения в другой проект не делал его пригодным. Документировать rotation и восстановление root key, не изобретать собственную криптографию.
- [ ] MP3.6. Повтор того же запроса/рестарт executor после любого шага не создаёт вторую БД или второго владельца. Проверять принадлежность уже существующих ресурсов операции/проекту, а не принимать ресурс только по совпадению имени. При частичной ошибке сохранять безопасный progress/error и выполнять явный retry; не удалять автоматически БД и не закрывать проблему бесконечным retry loop.
- [ ] MP3.7. Уникальные безопасные defaults: public registration и незаданные providers не включаются сами, email не помечается verified. Первый администратор проекта проходит одноразовый setup/invitation с существующими guards; отдельный общий default password запрещён. Credentials первого владельца не копируются из платформенного аккаунта.
- [ ] MP3.8. Фиксировать результат по стадиям и отдельно готовность storage/initial admin/configuration. SQL ready не означает настроенный SMTP/provider или завершённый admin MFA. Данные прежних проектов при ошибке создания нового не затрагиваются.

Готовность MP3: через API создаётся проект со своей БД; конкурентные повторы и остановка executor безопасно продолжаются; реальные инфраструктурные секреты в тестах не используются.

## MP4. Сборка Auth, подключения и workers

- [ ] MP4.1. Существующие feature services/repositories/handlers создаются для выбранного проекта с его зависимостями. В domain не протаскивать DSN/HTTP Host/глобальный service locator; не копировать фичи и не хранить изменяемый «текущий проект» в process-global переменной.
- [ ] MP4.2. Переиспользовать ограниченный runtime проекта между запросами: single-flight открытие, lease на время запроса/работы, закрытие неиспользуемого runtime, invalidation по версии настроек/credentials. Eviction не закрывает pool под активным запросом и не уничтожает SQL-сессии пользователей.
- [ ] MP4.3. Задать максимум resident runtimes и SQL connections суммарно по API instances, проектам, migrators и workers; отдельно оставить бюджет каталогу и управлению. MinConns не умножается без ограничений на все существующие проекты. На saturation — bounded wait/понятный отказ, не новая goroutine/connection без лимита.
- [ ] MP4.4. Независимые БД не должны создавать постоянный набор всех delivery/retention workers на каждый зарегистрированный проект. Планировать только ограниченное число работ/проектов одновременно, освобождать ресурсы, сохранять progress/lease и текущие SQL claim/idempotency гарантии. Не останавливать доставку outbox только потому, что нет пользовательского HTTP traffic.
- [ ] MP4.5. Общие ресурсы — hashing, HTTP admission, SQL/Redis/SMTP concurrency — имеют process-wide bounds и справедливые project budgets. Проектные limits не заменяют общий потолок, а отказ общего Redis не включает неограниченный SQL fallback. Shared transport допустим только без смешивания credentials/cookies/authority.
- [ ] MP4.6. Настройки метода/SMTP/provider/key rotation применяются только к соответствующему runtime и version. Отмена запроса и shutdown закрывают lease/rows/bodies/transactions, join workers выполняется до зависимостей. Смена проекта в UI не меняет уже исполняемый request context.

Готовность MP4: несколько проектов используют один код с ограниченными ресурсами; cold-open/eviction/update/shutdown проверены конкурентно, простой проект не расходует отдельный безлимитный pool/workers.

## MP5. Изоляция всех способов входа и настроек

- [ ] MP5.1. Проверить пользователей/contacts/credentials/external identities/roles/settings/audit и все pending flows. UUID не считается глобальным доказательством принадлежности: доступ разрешается только внутри подтверждённого проекта. Внешний backend также проверяет ожидаемые project/issuer/audience, а не принимает любой выданный Auth token.
- [ ] MP5.2. Redis namespace включает неизменяемый project ID и назначение: session coordination, throttling, OIDC state, OTP/MFA, idempotency и cache. Keyspace scan/FLUSHDB не используется для избирательного отключения проекта. Health общей Redis-зависимости и проектные ошибки различаются.
- [ ] MP5.3. Cookie/session/refresh proof одного проекта не принимается другим. Проверить rotation/logout/revoke/block/delete/reset/change email/mandatory MFA в проекте без влияния на соседний; сохранить немедленную SQL authority в существующих strict сценариях.
- [ ] MP5.4. Signing keys/JWT issuer и consumer trust задаются независимо по проекту. JWKS/cache/introspection credentials не выбираются только по kid, а непроверенный issuer не становится произвольным URL для загрузки ключей. Сохранить различие local expiry-window и strict online revoke, не обещать мгновенный отзыв локально проверяемого JWT.
- [ ] MP5.5. Google/Telegram callbacks и state/PKCE/nonce привязаны к проекту/назначению/браузеру/версии provider. Не принимать callback другого проекта, не объединять аккаунты по email. Отсутствующий проектный provider secret не заменяется секретом соседа.
- [ ] MP5.6. Проверить exact Origin/CORS/CSRF, доверенный ingress, HTTPS/cookie scope, redirect allowlists, email verification/reset/invite URLs. UI не меняет домены/issuer мимо этих правил; protected callbacks имеют свой явный контракт, не общий Origin bypass.
- [ ] MP5.7. SMTP/outbox/template payload и их encrypted поля принадлежат проекту. Mailer credentials, отправитель и пользовательские ссылки не смешиваются в общей доставке; повтор после временного отказа не меняет получателя/проект события.
- [ ] MP5.8. Настройки и роли сохраняют текущие version/delegation/last-admin/fresh-proof guards. Последний администратор проверяется отдельно для платформы и каждого проекта, не по общей сумме. Приостановка проекта закрывает новые запросы и pending completion согласно ADR; возобновление не оживляет отозванные токены. Уже начатые операции имеют явно проверяемый порядок приостановки, а не обещание мгновенно отменить произвольную транзакцию.

Готовность MP5: отрицательные cross-project тесты проходят для каждого опубликованного метода, не только password; правила одинаковы для прямого API и будущего UI.

## MP6. Обновления, перенос и эксплуатация

- [ ] MP6.1. Схемы всех проектных БД обновляются одним набором версионируемых миграций с ограниченным параллелизмом/lock wait и проверкой compatibility. Не переписывать уже применённые миграции и не выполнять миграцию из пользовательского HTTP request. Ошибка одного проекта видна, не маскируется общим release PASS.
- [ ] MP6.2. Уточнить restart/rolling upgrade: поддерживаемые версии каталога и project schema, остановка несовместимого runtime, maintenance/retry, rollback кода без разрушительного downgrade данных. Workers не обходят эти проверки.
- [ ] MP6.3. Существующую Auth БД подключить как явно зарегистрированный первый проект после проверки ownership/schema/grants. Не копировать автоматически всех пользователей в каталог и не менять их роли. Определить отдельный platform bootstrap и контролируемый переход URL/issuer/keys/Redis namespace; старые sessions/tokens либо безопасно переносятся с доказанными гарантиями, либо явно отзываются, не трактуются как глобальные.
- [ ] MP6.4. Отдельные backup/restore проекта и каталога, учёт потерянных после backup credentials/roles/MFA/settings, anti-rollback для ключей и согласование binding каталога с БД. Восстановление SQL само по себе не разрешает открыть traffic. Платформенный и проектный recovery используют явный target без произвольного DSN из запроса.
- [ ] MP6.5. Приостановка/resume проекта — обязательный безопасный сценарий. Безвозвратное удаление БД и автоматическое удаление backup не входят в обычный UI этого этапа: отдельная подтверждённая operator процедура. Никакого DROP/volume reset ради smoke test.
- [ ] MP6.6. Подготовить runbook переноса одной БД на другой заранее разрешённый сервер: maintenance/drain writers, backup/copy/verify, versioned rebind, закрытие старых runtimes/проверка split-brain и безопасное возобновление. Это управляемый перенос с возможным downtime; online migration/self-service cloud orchestration не обещаются.
- [ ] MP6.7. Конфигурацию deployment разделить с проектными настройками: platform DB/master key/trusted storage targets/общие resource ceilings — operational config, методы входа/SMTP/providers/роли — данные проекта. ENV-примеры и документация обновляются при реализации, реальные secrets не трогаются.
- [ ] MP6.8. Логи содержат безопасные project/operation identifiers и стадию, но не secrets/DSN/raw tokens. Контролировать connection wait/runtime count/provisioning retries/worker lag/error rate; не добавлять email/user IDs и безлимитные project labels во все metrics. Минимальные нужные метрики, без отдельной observability платформы ради симметрии.

Готовность MP6: новый и существующий проекты имеют проверяемые upgrade/recovery/maintenance процедуры; операции с чужими проектами и production данными не выполнялись ради проверки.

## Целевой API и UI контракт

Ниже ресурсные группы, не утверждение об уже существующих ручках. Точные paths/DTO/status codes фиксируются в MP1–MP3 и Swagger вместе с реализацией; не публиковать незавершённые endpoints.

| Операция | Защита и результат |
| --- | --- |
| Список/карточка проектов | Только platform read; bounded list, состояние/стадия/версия без DSN/secrets |
| Создать проект | Platform manage + fresh MFA, idempotency; accepted с project ID/стадией, не plaintext DB password |
| Повторить подготовку | Только recoverable состояние, версия/права; продолжение своей операции, не пересоздание готовой БД |
| Приостановить/возобновить | Platform manage + fresh MFA/version/audit; явная политика in-flight requests и workers |
| Настроить Auth/пользователей/роли | Project admin — свои существующие APIs; platform operator — отдельные platform endpoints/typed bridge с целевым проектом, SQL authority/audit, без project login/SSO |
| Первый владелец/восстановление | Одноразовый setup/invitation/recovery, без default password и автоматического входа в чужой проект |

Во время backend этапов достаточно Swagger/API и существующего разрешённого стенда. UI не требуется для проверки создания проекта.

## MP7. Функциональная и security приёмка

- [ ] MP7.1. Два проекта с одинаковыми email, разными login/registration/verification/MFA settings, custom roles и secrets. Проверить собственные first-admin/onboarding/recovery и управление настройками.
- [ ] MP7.2. Матрица «credential A → endpoint B»: cookie, JWT, refresh, service credentials, reset/verify/invite/temporary setup, email OTP, OIDC state/callback, MFA/recovery/link/unlink. Проверить одинаковые UUID/kid и reuse pending proof. Ни доступа, ни утечки существования чужих пользователей через детали ошибок.
- [ ] MP7.3. Platform/project administrator не взаимозаменяемы. Stale proofs/versions, self-promotion, last-admin, direct API/host/header tampering, untrusted issuer/redirect и случайный возврат default DB отклоняются.
- [ ] MP7.4. Concurrent create/retry/crash на стадиях, потеря ответа после фактического создания, зависший lease, migration error и безопасный restart. Не принимать чужую существующую БД/роль за результат операции.
- [ ] MP7.5. Отключение/версия настроек при pending login и активном runtime, rotation credentials, pool eviction при запросе, shutdown/cancellation. SQL отказ одного проекта не переключает запрос на другой; common catalog/Redis fault остаётся fail-closed согласно ADR.
- [ ] MP7.6. Сохранить текущие ordinary Auth/access/MFA contracts и immediate strict revoke; проверить outbox/retention/refresh-history cleanup принадлежность и worker coordination нескольких API instances. Использовать synthetic data, не повторять весь legacy набор после каждого мелкого изменения.
- [ ] MP7.7. Отчёт по этапу: commit/config/версии/PASS/FAIL/NOT RUN, SQL grants и isolation evidence. Внешние Google/Telegram/SMTP/browser/fleet проверки без условий не объявлять PASS. Найденный дефект исправить до перехода к UI, недоступный внешний gate явно согласовать.

## MP8. Финальная нагрузка перед UI

- [ ] MP8.1. Согласовать профиль2vCPU/4GiB: только Auth или весь Auth+SQL+Redis stack, реальные limits и распределение ресурсов, число проектов/активных пользователей, объём данных, latency/error criteria, безопасный потолок и запас генератора.
- [ ] MP8.2. Раздельные successful-RPS результаты sessions/roles, strict JWT/introspection, password login и mixed. JWT local измеряется у consumer, не как HTTP RPS Auth. Не отключать hashing/MFA/security quotas/SQL authority для красивых цифр.
- [ ] MP8.3. Активные и простаивающие проекты, cold opening/eviction, общий бюджет connections/workers, «шумный сосед» и несколько API instances. Рост числа проектов не должен давать неограниченный рост idle connections/goroutines.
- [ ] MP8.4. Warmup → ступени до нарушения согласованного критерия → повтор последней устойчивой ступени → длительный steady-state/load-rest/cleanup. Отдельно учитывать429/503 shedding/timeouts/drops и недоданную нагрузку генератора. После снижения нагрузки проверить recovery и отзыв.
- [ ] MP8.5. RSS/heap/allocations/горутин/GC наблюдения и целевые профили при признаках роста; private diagnostics с synthetic data, без публичного pprof и заранее заданного GC tuning. Поиск maximum прекращается до OOM/повреждения данных.
- [ ] MP8.6. Итог: последняя повторяемая pass-ступень, первая failed/неисследованная, bottleneck, p50/p95/p99, ресурсы/pools/backlog, рабочий запас и ограничения. Quota/generator/safety ceiling — нижняя граница, не выдуманный максимум. Старые50RPS/два load-rest окна сохраняются как исторический baseline.

## A7-projects. Общий UI после готового backend

- [ ] Стартовая настройка первого платформенного владельца, далее обязательный защищённый вход. Восстановление доступа не сбрасывает каталог или проектные БД.
- [ ] Список/создание/переключение проектов, progress/error/retry подготовки, понятное различие «storage ready», «admin настроен», «SMTP/provider доступен». Создание БД — backend операция, не подключение браузера к PostgreSQL.
- [ ] Раздельные platform и project экраны/полномочия. Выбранный проект явно виден; cache frontend/query keys разделены, при переключении не показываются старые карточки/secrets чужого проекта.
- [ ] Platform operator управляет всеми разрешёнными проектами из одной сессии панели, без повторного project login. UI обращается к platform management API, не пересылает platform cookie в project endpoints; обычный project admin остаётся в своей области. Это административные полномочия, не SSO для пользователей.
- [ ] Проектные пользователи/приглашения/временный пароль, custom roles/permissions, методы входа/verification/MFA, SMTP/providers и project JWT настройки поверх существующих защищённых API.
- [ ] Секреты: ввод/замена/проверка состояния без обратного чтения, ясные предупреждения о влиянии изменений. UI не хранит DB credentials/master key и не дублирует backend rules engine.
- [ ] Browser/API parity и сквозная A8: platform setup → проект A/B → admin/login/settings/users/roles → запрет cross-project доступа → recovery/disable/resume. DNS/TLS/ingress/provider checks выполнять при наличии условий, не заменять unit тестами.

## Что сознательно не делаем

- SSO/OAuth authorization server, общие аккаунты между проектами, организации, несколько приложений проекта и автоматическую миграцию пользователей между ними.
- Оплату/entitlements, произвольные бизнес-данные, универсальный plugin/DI framework и копии feature-кода под проекты.
- Одновременную поддержку shared tables/schema-per-project/database-per-project, отдельный Redis каждому проекту без требования, создание облачных серверов из UI.
- Мгновенный online перенос БД, автоматическое удаление данных/backup и универсальную платформу очередей/мониторинга.

## Условие перехода к UI

Порядок: MP1–MP6 с проверками по изменениям → MP7 cross-project приёмка → MP8 с актуальным capacity/длительными ресурсными прогонами → A7 → A8. Существующие локальные измерения сохраняются как baseline, не требуют формального повторения до MP1. Новый порядок не отменяет старые security prerequisites и не разрешает менять рабочие данные, создавать production БД или раскрывать реальные секреты без отдельного разрешения. При реализации сначала обновить архитектурный ADR, threat model, API/operations документы и целевые проверки; этот план не означает готовность multi-project.
