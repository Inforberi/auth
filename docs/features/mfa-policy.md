# Политика обязательности MFA

Подэтап A6.3m.3a подключает сохранённую политику к основным runtime-проверкам; проверки Luna V1/V2 PASS. A6.3m.2b добавляет выбор при первом setup; проверки Luna V1/V2 PASS. A6.3m.2c подключает защищённый HTTP API смены режима; проверки Luna V1/V2/V3 PASS.

## Целевое поведение

Владелец платформы выбирает обязательность MFA отдельно от проектов. В каждом проекте можно потребовать второй фактор для всех, для выбранных ролей либо оставить добровольное подключение. Уже подключённый личный фактор продолжает требоваться при входе после снятия обязательности. Требования назначенных ролей объединяются по OR; пользователь не может самостоятельно обойти обязательное для него правило.

Добровольность не отменяет свежую повторную аутентификацию перед критическими действиями. У администратора без личного фактора в optional-профиле остаются свежий пароль, действующие полномочия, Origin/CSRF и проверки версии. Если фактор подключён либо обязателен, нужен также свежий MFA proof. Отключение личного фактора требует текущего фактора или recovery proof; переключение политики не является восстановлением при потере факторов.

Полный план — [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). Optional-профиль нельзя публиковать до согласованного enforcement для login, SQL authority, management, native/JWT и уже выданных сессий.

## Разделение требований — A6.3m.1a

На этом подэтапе прежнее поведение было сохранено; настройки и optional-профиль добавлены следующими подэтапами ниже. В initial migration выделены две `STABLE`, `SECURITY INVOKER` SQL-функции:

| Правило | Применение | Текущий смысл |
| --- | --- | --- |
| `auth.has_administrative_access(user_id)` | Administrative password intent и лимиты SQL-сессий | System super_admin либо одно из восьми встроенных административных permissions, включая `accounts.users.read` |
| `auth.administrative_mfa_required(user_id)` | MFA status и запрет отключения фактора | System super_admin либо одно из семи управляющих permissions; `accounts.users.read` само по себе сюда не входит |
| `auth.role_requires_mfa(user_id)` | Существующее требование ролей при входе и управлении фактором | Хотя бы одна назначенная роль с `mfa_required=true` |

Первые две функции классифицируют назначения, но не предоставляют полномочия: они не проверяют пароль, действительность сессии или status аккаунта. Эти проверки остаются у вызывающего сценария. SQL вызывается в том же statement и транзакции, без новых round trips, pools, cache или фоновых задач. Функции работают с правами вызывающей DB-роли и не обходят отсутствие SELECT grants.

Не объединяем административные ограничения сессии и запрет отключения MFA в один boolean: это изменило бы поведение read-only администратора. Также наличие личного TOTP, обязательность роли и свежесть proof — самостоятельные гарантии.

На этапе 1a platform password/TOTP guards и usable-administrator prerequisites не менялись. Подэтап 3a ниже заменяет безусловность MFA текущей политикой, сохраняя пароль и authority. Bootstrap и project bridge capability guards не ослаблены. Schema изменена в исходной миграции по принятому для текущей разработки правилу; рабочие БД автоматически не меняются.

## Сохранение политики — A6.3m.2a

На этапе 2a подготовлено внутреннее хранение. Mode применяется runtime-проверками подэтапа 3a; HTTP API добавлен в подэтапе 2c.

В каждой Auth schema существует собственная строка `auth.mfa_settings`: `version` и `mode`. Платформа и отдельные project БД не разделяют её. Начальная миграция создаёт `version=1, mode=administrators`; runtime не выполняет Initialize, не восстанавливает строку и не использует ENV fallback. Standalone/platform startup и подготовка project onboarding проверяют наличие и допустимость настройки. Рабочие БД этим изменением не сбрасываются и автоматически не мигрируются.

| Сохраняемый mode | Назначение для следующего этапа enforcement |
| --- | --- |
| `optional` | Добровольное личное подключение; требования ролей и уже подключённые факторы сохраняются |
| `administrators` | Обязательность для администраторов, добровольность для остальных; на платформе охватывает операторов |
| `required` | Обязательность для всех пользователей realm |

Отдельный `roles` mode не нужен: выбор обязательных ролей уже хранится в их `mfaRequired` и объединяется по OR с realm policy. Новых role tables/permissions не добавляется. Конкретные ранее различавшиеся administrative login/disable правила сохраняются до согласованного переключения enforcement, а не заменяются одним флагом в этом подэтапе.

Внутренние entrypoints:

- `settings/service.MFA.Current/Read/Update` — конфигурация и защищённое локальное управление для standalone/project. Чтение требует живую локальную сессию и `auth.settings.manage`; запись также проверяет свежие пароль/MFA и блокирует authority через существующий Access guard.
- `operator.Repository.ReadMFAPolicy/UpdateMFAPolicy` — политика платформы. Используются собственные platform realm/session/permission guards с `platform.project_settings.manage`. Локальная Auth-роль не подменяет полномочия оператора.
- `ApplyMFAPolicyChange` — общая транзакционная запись после caller-owned authority locks; это не публичный административный API.

Запись проверяет положительную ожидаемую версию и допустимый mode, блокирует singleton, сверяет версию, затем атомарно меняет policy и добавляет `auth.mfa_settings_audit`. No-op сохраняет версию и не создаёт audit; устаревшая версия даёт conflict; ошибка audit откатывает изменение. Выбор нового обязательного режима требует trusted MFA readiness из backend assembly, не значения из запроса. У уже сохранённого no-op такое требование повторно не возникает. Readiness платформы не используется вместо project readiness.

Операции ограничены deadline 3 секунды; используются существующие пулы и locks. Нет массового UPDATE пользователей/сессий, новых workers, кеша или polling. Audit включён в существующую очистку security audit с прежними размером партии, индексом `(created_at,id)` и сроком хранения. Фактор и recovery codes при сохранении режима не удаляются.

Domain-тесты и SQL fixture добавлены для mode validation, прав, no-op, capability denial, конфликтов и конкурентных записей, отката при отказе audit, сохранения роли/фактора и missing-row без seed. Platform fixture проверяет отдельную authority и wrong-realm отказ. Luna V1/V2: Go tests, targeted race, полный Linux ARM64 command SQL, четыре schema-теста, platform operators/MFA settings, operator HTTPS и lint закреплённой v2.14.0 — PASS. Все 17 source hashes совпали со снимком; временные fixtures удалены. Этот PASS относился только к storage: последующие runtime, first-run и HTTP изменения описаны ниже; полная двухпроектная матрица остаётся открытой.

## Применение в runtime — A6.3m.3a

SQL рассчитывает три отдельных условия: `realm_requires_mfa` для realm policy, `mfa_required` для объединения её с назначенными ролями и `mfa_login_required` для добавления уже подключённого личного фактора. Default `administrators` сохраняет различие между управляющими permissions и одним read-only administrative session profile; явный административный login intent также требует MFA. Optional не отменяет выбранные role requirements или личный фактор.

Browser и native password/email/OIDC paths используют общий SQL-расчёт и существующие MFA coordinators. При обязательности без фактора допускается только ограниченный challenge/enrollment, не полноценная сессия; это относится и к корректному administrative password intent. В optional-режиме администратор без фактора получает обычную password session со свежим серверным password proof. Проверка permanent password, verified email и текущих административных полномочий сохраняется.

`auth.role_bound_sessions` дополнительно проверяет ревизию MFA policy и фактический MFA proof, когда он нужен. Эту view уже используют session middleware, mutations, native refresh, exchange и SQL introspection. При усилении mode увеличивается `mfa_settings.session_revision`: все сессии предыдущей ревизии требуют нового входа, pending MFA login также привязан к ревизии. Смягчение её не уменьшает, поэтому старые токены/challenges не оживают. Это одна строка настроек, без массового UPDATE users/sessions. Issuance и завершение challenge используют существующий общий Access lock до user locks; финальный SQL recheck обязателен.

Проверка JWT без обращения к Auth не получает мгновенный отзыв: ранее выданный access JWT остаётся ограничен своим TTL и существующим online/offline контрактом. Новый SQL/view guard действует для выдачи, refresh и online introspection; универсального обещания немедленного отзыва offline JWT нет.

Локальные и platform mutations всегда требуют свежий password proof; свежий MFA proof добавляется, если обязателен режимом/ролью либо фактор подключён. Realm/session/permission/version locks и deadlines сохранены. Last-admin credential check учитывает optional без скрытого обязательного enrollment. Отключение личного фактора по-прежнему требует свежий primary и проверку действующего фактора/recovery; оно не заменяется mode toggle. Delivery initial email binding учитывает ту же conditional MFA authority; final confirmation независимо перепроверяет права.

Статус MFA дополнен `requiredByPolicy`; `disableAllowedByPolicy` учитывает его вместе с ролью и административной обязанностью. Swagger обновлён: administrative login может вернуть 200 session либо 202 challenge. HTTP API опубликован позднее, в подэтапе 2c ниже. Отключение технической MFA capability на standalone отклоняется при enrolled factors, required roles либо требующем её realm profile.

Добавлены SQL-сценарии optional administrator, обязательного enrollment, гонки issuance/усиления, stale sessions/challenges и отсутствия revival после смягчения. Platform fixture проверяет optional operator с fresh password без TOTP, stale password refusal и сохранение защиты уже подключённого фактора. Legacy storage tests получают новую login session после усиления вместо обхода immutable revision. Luna V1/V2: task check/API, targeted race, полный Linux ARM64 command SQL, schema enforcement/role/administrative/native/JWT/refresh, platform optional authority и operator HTTPS — PASS. V2 восстановил conditional FOR SHARE фактора и согласовал ограниченный administrative enrollment со schema. Все 35 source hashes и Swagger artifacts совпали со снимком; fixtures удалены. First-run, capability matrix и settings HTTP были проверены следующими подэтапами ниже.

## Границы приёмки

Capability/readiness, защищённый HTTP API и личная MFA операторов реализованы в подэтапах 5a, 2c и 3b ниже. Их пройденные проверки не заменяют полную двухпроектную приёмку и проверки реальных провайдеров. Required нельзя включить без готовой capability. Platform MFA readiness не заменяет project MFA readiness.

### Первый запуск — A6.3m.2b

[Контракт setup](initial-setup.md): оператор с существующим installation proof выбирает `mfaMode` при start. Optional подтверждает email без enrollment; administrators/required завершают email+TOTP до создания владельца. Отсутствующее поле и прежние pending intents сохраняют administrators. Completion не принимает режим и не выдаёт сессию. Режим сохраняется существующим version/audit writer атомарно с Auth owner и platform authority; rollback не оставляет новую policy. Setup marker, operator pin, TTL, cooldown и attempts сохранены. Optional не генерирует factor/recovery data. Technical MFA capability для setup остаётся обязательной; project disabled/readiness matrix проверена в подэтапе 5a ниже. Проверки Luna V1/V2 PASS: Go tests/API/race, setup SQL трёх режимов, platform rollback/owner authority и operator HTTPS. Manifest20 совпал с main, fixtures очищены. Личная MFA optional platform profile проверена в подэтапе 3b ниже; полная межпроектная приёмка остаётся отдельной.

Границы оставшейся приёмки перечислены в дополнении A6.3m.5b. Наличие backend API не разрешает начинать UI без отдельного согласования.

## Совместимость capability — A6.3m.5a

Проверки Luna V1/V2/V3 PASS. `optional` описывает обязанность пользователя, а не выключение engine. Платформа и первый setup по-прежнему требуют техническую `MFA_ENABLED=true`: optional-владелец не обязан подключать TOTP, но механизм доступен для последующего подключения и step-up. Нового ENV или автоматического изменения сохранённой политики нет.

Общий SQL `CheckCapability` проверяет существующую валидную MFA policy. При выключенном engine дополнительно запрещает enrolled TOTP, любую MFA-required роль (включая пока не назначенную), режим required и administrators при наличии соответствующего административного назначения. Optional без факторов и обязательных ролей совместим с выключенным engine. Missing/invalid policy не принимается за optional и не восстанавливается из ENV. Старый CheckDisabled использует ту же проверку.

`BuildProjectProfile` и assessment вызывают её один раз до сборки компонентов, на lease только выбранной проектной БД. Любой настроенный browser/native путь без MFA engine обязан пройти disabled-проверку; несогласованные browser-конфигурации дополнительно отклоняются прежними guards. Конфликт не публикует готовый route plan. Для закрытого профиля без primary-конфигурации проверяется policy, но отсутствие login capability само по себе не запрещает read/session-management API. Существующая native-конфигурация продолжает требовать доступный engine.

Это проверка сборки, не новая кешированная authority: окончательные SQL/session/challenge guards сохраняются. В уже собранном профиле смена политики всё равно применяется через SQL; декларация readiness — наблюдение, а не разрешение обхода. В горячий путь входа новые запросы не добавлены, проверки факторов/ролей используют bounded EXISTS без обхода всех пользователей. Deployment rollback должен учитывать всех пользователей и MFA-required роли, а не только настройки оператора.

Тестовая матрица включает optional/admin/required с engine on/off, missing policy, unassigned MFA role и личный фактор; optional factorless last-admin с verified permanent credential; реальные project profile/management readiness и независимость platform policy. Last-admin не отменяет fresh primary proof, права, verified email или recovery-процедуру. Полная двухпроектная приёмка, защищённый API переключения политики и UI остаются отдельными gates.

## HTTP API политики — A6.3m.2c

Проверки Luna V1/V2/V3 PASS. Это политика текущего realm, а не управление MFA соседних БД из platform session. Межпроектный bridge для этой настройки отдельно не добавляется.

| Режим приложения | Ручки | Полномочия |
| --- | --- | --- |
| Standalone | GET/POST `/api/v1/admin/auth/settings/mfa` | `auth.settings.manage` текущей Auth-БД |
| Внутри независимого проекта | Те же пути на origin проекта | Проектная session и `auth.settings.manage`; deployment manifest `mfaSettings:true`, по умолчанию выключено |
| Платформа | GET/POST `/api/v1/platform/settings/mfa` | Platform session и `platform.project_settings.manage`; локальная Auth-роль её не заменяет |

Для всех маршрутов обязательны разрешённый HTTPS Origin, cookie session и существующая browser protection. Используется NoRefreshAuth: GET/POST не продлевают срок сессии и не выдают новую cookie. Чтение требует текущие полномочия, изменение дополнительно fresh password и fresh MFA, если её требует realm/роль/личный фактор. Необходимые SQL locks, final authority, audit rollback и version-check выполняет прежний writer.

GET возвращает, например:

```json
{"version":3,"policy":{"mode":"optional"}}
```

POST принимает полный mode и положительную текущую версию:

```json
{"expectedVersion":3,"policy":{"mode":"required"}}
```

Возможные значения `optional`, `administrators`, `required`. Не принимаются actor, realm/project ID, capability/ready, factor state или произвольные permissions. Неверная форма/неизвестные поля — `400 invalid_json`; невалидный mode/version — `400 invalid_mfa_policy`. Конфликт версии — `409 mfa_policy_conflict`; недостаточная серверная MFA capability — `409 mfa_not_ready`; нет сессии —401; нет текущего права —403; устаревшие proofs — `403 fresh_auth_required`; инфраструктурная ошибка —503 без внутренних данных.

POST возвращает200 с сохранённой version/policy. No-op сохраняет version и не добавляет audit. Усиление повышает session_revision и немедленно лишает силы все прежние realm sessions/login challenges, включая сессию инициатора, но не отменяет уже совершённую транзакцию. Ответ200 передаёт committed state; следующий запрос со старой cookie получает401. Клиент заново входит и читает актуальную политику. Потерянный ответ нельзя трактовать как гарантированный rollback или повод повторять смену без чтения. Смягчение не удаляет личные факторы и не возвращает силу ранее отозванным сессиям. Offline JWT остаются ограничены своим TTL, online guards используют SQL.

Project adapter берёт один scoped lease с пятисекундным пределом, проверяет каталог до и после операции; повторная проверка actor после собственного policy commit не выполняется. MFA readiness принадлежит сборке выбранного проекта, не платформе и не JSON body. При доступном browser transport POST допускается и без MFA engine: existing writer разрешает optional/no-op и запрещает включение обязательности без готового engine. Проверка совместимости профиля по A6.3m.5a сохраняется.

Platform profile подключает existing login enrollment start/confirm и owner TOTP enrollment start/confirm: после включения обязательности оператор без фактора может завершить ограниченный flow до выдачи сессии. A6.3m.3b ниже дополняет это DELETE личного platform TOTP; проверки Luna V1/V2/V3 PASS. Платформенный engine по-прежнему обязателен технически. UI не начинался.

HTTP unit/contracts и SQL HTTPS сценарии добавлены для session/Origin/permissions, client authority rejection, version/no-op/audit, weakening with personal factor, strengthening with own-session revocation и project/platform isolation. Luna: task check/API, targeted lint/race, schema policy/runtime/capability SQL, platform operators, полный ARM64 command SQL и operator HTTPS PASS. V2/V3 исправили только test fixtures; manifest33 совпал с main, fixtures очищены. Подробные evidence и первые FAIL в history.

## Личная MFA операторов — A6.3m.3b

Проверки Luna V1/V2/V3 PASS, 31 октября. Платформа использует прежние status/enrollment/step-up/replacement/recovery-code ручки и дополнительно `DELETE /api/v1/auth/mfa/totp`. Проверяются session/Origin и fresh password+MFA; recovery-код сначала потребляется через `/api/v1/auth/mfa/step-up`, который меняет verifier cookie. DELETE не принимает код или административный intent от клиента.

Trusted platform assembly создаёт `mfa.Repository.NewPlatform`: administrative intent фиксирован внутри репозитория и применяется при Status/Disable. Он не зависит от наличия локальной роли Auth-admin или конкретного platform permission. Поэтому operator без local Auth-role не может отключить фактор при `administrators`/`required`; обязательные роли также сохраняют требование в optional. Standalone и проекты используют прежние конструкторы и свои правила. Новых полей в HTTP DTO/service.Proof, ENV или schema нет.

Optional разрешает отключение только со свежими proofs. Удаление фактора каскадно удаляет recovery digests, повышает auth_version, отзывает все сессии пользователя и удаляет pending enrollment/login challenges в прежней транзакции под Access lock. Ответ200 очищает cookie; старые сессии получают401. После нового парольного входа optional-оператор без фактора может подключить TOTP снова. Если policy усилена до required, вход возвращает только bound enrollment challenge; до подтверждения и повторного входа полноценной session нет. Ослабление режима не удаляет личный фактор, а recovery-code replay запрещён. Потеря всех факторов остаётся отдельным recovery flow, не способом выключить обязательность.

Добавлены SQL-проверки platform-only intent/status/disable, required/optional/custom-role OR, stale proofs, cascade/revoke/audit; HTTPS-сценарий проверяет policy denial, recovery step-up/rotation/replay, optional disable/password-only login, доступность voluntary enrollment и forced enrollment после required с повторным MFA-входом. Existing loss-all-factors и last-admin suites остаются regression gates. Полная двухпроектная/resource/release приёмка этим подэтапом не закрывается.

## Проверки подэтапа

### Дополнение матрицы — A6.3m.5b

Проверки Luna V1/V2 PASS, 31 октября. Task check/fullGo/pinned lint и SQL regression пройдены на V1; оба новых SQL-сценария прошли с race по три раза (primary matrix — на V2 после исправления уникальности synthetic subject). Проверенные Go-файлы совпали с V2 перед коммитом; fixtures очищены. Подробные логи и первый FAIL — в history.

| Гарантия | Проверка | Граница |
| --- | --- | --- |
| Google/Telegram/email OTP: добровольный вход без фактора, обязательное enrollment от роли либо realm, сохранение личного фактора после смягчения | `TestRoleMFAOtherPrimaryMethods` | SQL/coordinator fixtures; не реальная проверка assertions провайдеров или доставки почты |
| Отключение TOTP против усиления realm либо назначенной роли | `TestMFAPolicyFactorRacesSchema` | Оба последовательных порядка и конкурентный запуск; актуальная обязательность, сохранность фактора при отказе, auth_version, отзыв старой сессии и запрет новой factorless session |

Предыдущие PASS для recovery/replay/last-admin, first-run и platform↔project остаются действительными для своих снимков. На момент 5b отдельно оставались двухпроектная приёмка, native/JWT matrix, внешние провайдеры и UI. Native/JWT SQL matrix принята в 5c ниже; остальные gates этим не закрыты. Общая schema regression не объявляется доказательством каждой комбинации. Email/Telegram как **второй** фактор ещё не реализованы; это A6.3m.6, отдельный от существующих основных методов входа.

### Предыдущая приёмка предикатов — A6.3m.1a

Сведения ниже относятся к прежнему подэтапу; native/JWT matrix имеет отдельную приёмку 5c ниже.

`TestMFARequirementPredicatesSchema` проверяет все восемь permissions и обычное продуктовое permission, system administrator, объединение/отзыв ролей и invoker ACL. Существующие SQL-сценарии подтвердили сохранение административного login, MFA status/disable, длительностей сессий и platform/project readiness. Luna V1: task check, targeted race и полный Linux ARM64 TestPrepareCommandSQL — PASS. После исправления параметризованных multi-statement запросов в новом fixture Luna V2 подтвердила targeted lint (0 issues) и все шесть schema-тестов в штатном query mode. Все шесть source hashes совпали со снимком и рабочими файлами; временные стенды удалены.

### Native и JWT — A6.3m.5c

Luna V1 PASS, 31 октября: task check и оба отдельных SQL integration tests с race на Linux ARM64/TLS/SCRAM, без SKIP. Все шесть snapshot hashes совпали до/после; оба Go-файла совпали с main перед коммитом. Own fixture удалён. Evidence/exit-коды `/private/tmp/auth-mfa-native-jwt-v1-*`.

- `TestMFAPolicyNativeSchema`: password/email OTP × realm/role. В optional без фактора выдаются API credentials без ложного MFA assurance. Ужесточение закрывает старые refresh и online introspection; вход возвращает только native enrollment challenge. Подтверждение TOTP не выдаёт credentials; новый primary login и recovery-code completion дают JWT с фактическими primary/mfa claims. После смягчения личный фактор сохраняется, новый вход по-прежнему требует MFA; старые credentials не оживают, refresh новой MFA family сохраняет assurance.
- `TestMFAPolicyJWTConsumersSchema`: realm/role × primary-only/enrolled. Browser session exchange и online SQL introspection работают в optional, старые sessions/JWT authority отвергаются после ужесточения и после смягчения. Личный фактор завершается настоящим recovery-code workflow, не прямой записью mfa_verified_at; claims сохраняют pwd/mfa и MFATime. После смягчения возможен новый вход с актуальным требованием.

Изменения политики проходят существующие versioned/audited service/repository writers. Тестовые management actors используют прежние synthetic fresh proofs; пользовательские enrollment/completion — реальные SQL workflows. Нет новых production-проверок, SQL round trips в hot path, API, ENV, schema или зависимостей. Offline signature verification отдельно остаётся успешной до JWT expiry даже при online-отзыве; этот тест не обещает мгновенную автономную ревокацию. HTTP/provider assertions, fleet/сеть и полная двухпроектная приёмка остаются отдельными gates.

### Межпроектная изоляция — A6.3m.5d

`TestMFAProjectIsolationSQL` принят: Luna V1/V2/V3 PASS, 31 октября. Full Go tests и JWT SQL regression прошли в V1, isolation SQL с race — в V2, финальный pinned lint — в V3 (0 issues). Проверенные Go-файлы совпали с main перед коммитом; own БД/роли удалены, Redis DB15 пуст. Это component-level приёмка реальных SQL services и scoped crypto/Redis, не полный запуск двух `ProjectProfile` через HTTP dispatcher.

Fixture создаёт три отдельные одноразовые БД: `auth_mfa_isolation_a_test`, `auth_mfa_isolation_b_test`, `auth_mfa_isolation_platform_test`. У каждой собственная SQL login-role/owner; PUBLIC CONNECT отозван, попытки подключения чужими credentials отвергаются. User UUID, email и synthetic первичный password proof намеренно одинаковы. MFA root key также одинаков, но realm purposes разные; чужие ciphertext не открываются, HMAC digests различаются. JWT keys/issuers независимы при одинаковом kid, чужой issuer отвергается даже с его правильным публичным ключом.

Проверяются все направления cross-realm session lookup/exchange, signed JWT verification/online introspection и refresh. Challenge/enrollment проекта A не принимается B или платформой. Изменения realm policy и роли, реальное TOTP enrollment/recovery completion и отключение фактора выполняются в A. После каждого этапа сравнивается SHA-256 полного упорядоченного JSON-состояния соседних users/roles/permissions/assignments/sessions/MFA pending/factors/recovery/refresh/audits, а не только количества строк; прежние соседние sessions/JWT остаются действующими, их native refresh успешно завершается в конце. В A ужесточение закрывает прежние credentials, required role сохраняет MFA после смягчения realm, личный фактор продолжает требоваться до защищённого Disable.

Отдельный подэтап на общем реальном Redis DB15 проверяет независимость literal project/user MFA budgets через штатный scoped Lua adapter. SQL-сценарий MFA использует существующий test limiter; это не проверка admission всей project assembly. Redis ключи удаляются по точному списку; FLUSHDB/scan не используются.

Запуск требует `AUTH_MFA_ISOLATION_TEST_DATABASE_URL` с явным loopback `127.0.0.1`, database `auth_storage_test`, user `auth` на отдельном disposable PG, плюс отдельный пустой Redis DB15 через `AUTH_PROJECT_PASSWORD_TEST_REDIS_ADDR`. Это только test ENV, не новая настройка продукта. Fixture отказывается заменять существующие БД/роли и очищает только созданные ею ресурсы. Подготовку/прогон/cleanup выполняет Luna.

Не закрываются provisioning/runtime credential reader/registry, реальные HTTP cookies/Origin/CSRF/ingress, operator-authority bridge, внешние providers/SMTP и остальные MP5 flows. Их существующие локальные PASS и оставшиеся end-to-end gates учитываются отдельно. Ни этот тест, ни отдельная MFA matrix не означают полную MP5 или production sign-off.

Приёмка 5d исправила только test fixtures: внешний ctx передаётся helpers; перед Disable выполняется отдельная ConfirmPassword transaction с checked synthetic hash/current version и ротацией cookie. MFA login сам не заменяет fresh private-admin password proof. Production guards не менялись. Snapshot V3 `/private/tmp/auth-mfa-realm-isolation-v3.jou1lmaw`, manifest9/metadata рядом, evidence/exit-коды `/private/tmp/auth-mfa-realm-isolation-v{1,2,3}-*`; первый FAIL сохранён в history.

### Два проекта через HTTPS — A6.3m.5e

Отдельный `TestTwoProjectHTTPIsolationSQL` принят Luna V2, 31 октября: task check и SQL/HTTPS с race на Linux ARM64/TLS/SCRAM PASS. V1 внутри старого nested drill остановился на корректной DDL-блокировке A; V2 готовит оба проекта последовательно в независимой фикстуре, закрывая подготовительный connection/lock перед следующим проектом. Каждый проект получает собственные database/owner/runtime role через реальные `project-prepare -schema -secrets -password -managed` и `ActivateManagedRuntime`. Оба подключаются к настоящим RuntimeCredentialReader, двухместному Registry и NewProjectHTTP/ProjectProfile/runtime dispatcher. Readiness и project identity/grants проверяются штатным connection attestation.

На реальном локальном TLS server проверяются вход в оба проекта с одинаковым user UUID/email/password, host-only Secure/HttpOnly/SameSite cookies, отказ чужим session cookies и MFA binding/challenge/enrollment/confirmation/completion. MFA enrollment A не выдаёт полноценную сессию; новый primary+recovery login выдаёт её только в A. B сохраняет свой factorless профиль и действующую сессию. Missing/foreign Origin отвергает login и logout; чужой Origin/OPTIONS не получает CORS-разрешение. X-Project-ID и недоверенные X-Forwarded-* не выбирают A вместо B; неизвестный/platform Host и plaintext HTTP закрыты. При suspended A уже прогретый профиль не принимает сессию или pending MFA completion, B продолжает вход и обслуживание прежней сессии. Platform Auth/MFA settings, operator realm/permissions и sessions не изменяются.

Публикация fixture в `phase=ready` и переключение `desired_state` выполняются напрямую в одноразовом каталоге по образцу прежних runtime drills. Это проверка HTTP enforcement реального reader/registry, а не lifecycle command permissions/audit/finish-preparation API. Конфигурацию профилей задаёт trusted test source; manifest loader уже имеет отдельные проверки. Cookie attacks отправляются вручную через HTTP client: реальный браузер/cookie jar/DNS/внешний reverse proxy/fleet остаются отдельной приёмкой. Billing/SSO/UI не добавляются.

Cleanup закрывает server/profile registry/пулы до удаления созданных fixture A/B и их пользователей/БД/ролей, затем удаляет собственные catalogue/storage schemas и служебные роли. Redis DB15 изолирован; удаляются только вычисленные project/purpose keys, без scan/FLUSHDB. Production/API/schema/dependencies и ENV продукта не меняются. Полный MP5, providers/SMTP и эксплуатационная ingress-приёмка не закрываются этим сценарием.

Приёмка 5e V2: manifest11 совпал до/после, все5 Go-файлов совпали с main перед коммитом. Own DB/roles A/B, schemas и fixture roles удалены, RedisDB15 пуст. Snapshot `/private/tmp/auth-two-project-https-v2.ugnwfmas`, evidence/exit-коды `/private/tmp/auth-two-project-https-v2-*`; первый V1 FAIL сохранён в history.

## Метод подтверждения — A6.3m.6a

Принята первая часть A6.3m.6: Luna V1 task check/affected package races/core TestPostgresSchema/two-project HTTPS PASS, V2 targeted platform lint/SQL race PASS. Штатный cleanup/manifest42 подтверждены; main сверил все42 файла/base HEAD со снимком перед итоговым обновлением Markdown, Go/SQL не менялись. Отменяемый revoke в старом platform lock test изолирован explicit transaction/rollback; production authority не ослаблялась. Новых endpoint/settings/factors пока нет. Существующий consumeFactor возвращает Method/VerifiedAt только после успешного одноразового TOTP/recovery consume и аудита; browser login, native issuance и step-up сохраняют оба значения атомарно. SQL владеет временем, клиент не выбирает результат проверки через JSON. Recovery остаётся разрешённым существующим способом, его одноразовость/TTL/отзыв/права не ослабляются.

Session domain/validation/HTTP auth context передают записанный метод; JWT exchange/native/refresh формируют otp/recovery из SQL, introspection сверяет точный метод и время. Поля времени и метода не создают отдельный клиентский assurance-флаг. Исторические proofs без метода не объявляются TOTP: NULL сохраняет прежний coarse mfa и текущие enrollment/freshness/role guards. Новые успешные проверки всегда записывают конкретный метод; отключение proof требует очистить и метод.

В prerelease исходной migration добавлен nullable mfa_method: только totp/recovery, непустой метод требует MFA timestamp. role_bound_sessions отдельно ограничивает известные proof-классы. Email/Telegram значения не допускаются и не могут получить critical authority через общий timestamp. До их публикации следующий подэтап должен определить method-aware login/step-up/native/JWT/critical requirements и permitted combinations primary+second factor; просто расширить CHECK и считать всё MFATime запрещено. Наличие TOTP enrollment не доказывает, что использован именно TOTP.

Source baseline изменён без отдельной migration по текущему prerelease-порядку. Реальные DB/env не менялись; upgrade существующих БД/rolling compatibility не заявлены и остаются MP6. Для проверки достаточно task check, race affected packages, SQL browser/native/step-up/claims/refresh/constraints и platform authority на own fixture, плюс двухпроектный HTTPS regression. Внешние provider/UI/load проверки этим этапом не закрываются.

## Строгий proof для критических действий — A6.3m.6b

Принята часть A6.3m.6b: Luna V1 task check/affected races/core schema/platform operators/two-project Access и V2 targeted lint/operator HTTPS race PASS. Штатный cleanup/manifest36 подтверждены; main сверил все36 файлов/base HEAD со снимком перед итоговым обновлением Markdown, Go/SQL не менялись. Единственная V2 code delta — пароль own recovery fixture login для SCRAM, production recovery guard прежний. Обычная действующая session и строгий MFA proof разделены: role_bound_sessions сохраняет прежнюю применимость session, но вычисляет strong_mfa_verified_at только для записанных totp/recovery. Исторический NULL method не получает строгий proof по одному timestamp. Новых factor labels/schema tables/endpoints/settings нет; email/Telegram по-прежнему не допускаются SQL CHECK.

Access mutations, platform read/mutation authority, account/email-binding guards, delivery approver checks и MFA-management/status читают strong timestamp; прежние сроки свежести, SQL clock/deadline, Access locks и окончательные checks при commit сохраняются. Это не вводит обязательную MFA вопреки optional policy: когда действующая realm/role/personal policy не требует фактора, прежний password-only вариант остаётся. Если MFA требуется или управляется уже подключённый фактор, неизвестный historical method требует существующего TOTP/recovery step-up. Обычная session остаётся действующей; статус FreshMFAProof=false объясняет необходимость подтверждения. Step-up ротирует token и записывает известный method, после него защищённые действия снова доступны.

JWT exchange/native/refresh/introspection сохраняют контракт .6a, включая coarse mfa для historical proof. Для внешнего backend добавлен явный opt-in RequireStrongMFA(maxAge) после Consumer.Middleware и вместе с RequirePermissions. Он допускает только otp/recovery + primary, требует timestamp не из будущего и возраст строго меньше maxAge; допустимая startup настройка maxAge — (0,15m]. Legacy mfa, missing/unknown/email/Telegram labels и stale proof не повышаются до строгого. Anonymous/expired principal даёт401, недостаточный proof403 strong_mfa_required/no-store. Principal возвращает defensive-copy AuthenticationMethods и MFAVerifiedAt, не принимает claims от клиента в context.

Strong guard не заменяет permission/object/field guards и не добавляет online authority в local JWT mode: срок отзыва остаётся прежним TTL/strict режимом Consumer. Никакого автоматического downgrade или выбора другого фактора нет. Primary/second-factor independence и доступные способы пользователя станут частью реализации новых email/Telegram flow, не считаются закрытыми этим этапом.

В schema baseline изменена только projection существующей view, без новой функции/grants/round trips/индекса. Synthetic completed TOTP fixtures теперь задают method явно; новый SQL negative case сохраняет ordinary historical session, отказывает factor mutation до реального recovery step-up. Проверки — task check, affected race, core schema/platform authority/оператор HTTPS/two-project access, включая обновляемость view и собственный cleanup. Existing DB/view upgrade и rolling compatibility отдельно MP6; реальные env/data не меняются.

## Подготовка email-канала — A6.3m.6c.1

Подготовлен [внутренний email possession workflow](email-mfa.md) на существующих OTP outbox/delivery и session proofs, проверки Luna пройдены. Request/confirm связаны с текущей password/browser session и owned verified email, исходным hash/version, отдельным code purpose и строгой MFA по действующей policy. Ротируется только текущий token, но не включается фактор/новый вход и не повышается assurance. Сохраняются разные pending purposes; expiry/attempts/authority/аудит проверяются SQL.

До публикации обязательны A6.3m.6c.2 activation/policy/выбор и .6c.3 atomic login/native enforcement с channel independence. Новых HTTP/ENV/startup flags/UI пока нет; не считать EmailPreparation уже работающим email MFA.

## Управление email-фактором — A6.3m.6c.2

[Внутренний lifecycle](email-mfa.md#внутреннее-управление--a63m6c2) отделяет разрешение проекта от личной привязки. Policy/version/permissions и fresh password/email/current strong proofs проверяются транзакционно; Enable/Disable отзывают credentials, email change приостанавливает прежний binding без auto-downgrade. Luna task check/race/пять SQL roots PASS, manifest 25/25 и cleanup подтверждены. Публичных флагов/маршрутов нет; runtime закрыт до .6c.3–.6c.4. Email-only completion/recovery/step-up и финальный выбор факторов ещё не реализованы, TOTP/recovery остаются единственным strong proof.

## Email после пароля — A6.3m.6c.3

Принят [внутренний browser/native login и assisted recovery](email-mfa.md#внутренний-вход-и-восстановление--a63m6c3): Luna task check, token service race и девять SQL roots с учётом V1/V3 PASS; manifest 48/48 и cleanup подтверждены. SQL proof различает usable email и TOTP/recovery, JWT сохраняет pwd+email_otp; strict guards не повышают email до strong. Email-only личный фактор можно отключить по optional policy после fresh password/current email proof, обязательный последний фактор сохраняется. При потере почты существующее operator-approved восстановление заменяет email-only на подтверждённый новый TOTP и отзывает credentials. Usability потерянной почты для этого восстановления не требуется; отдельные primary/operator/new-factor proofs обязательны. Capability/HTTP/profile publication остаются закрыты до .6c.4.
