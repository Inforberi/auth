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

Предыдущие PASS для recovery/replay/last-admin, first-run и platform↔project остаются действительными для своих снимков. Отдельно остаются полная приёмка двух проектных БД, выделенная optional/required матрица native/JWT, внешние провайдеры и UI. Общая schema regression не объявляется доказательством каждой комбинации. Email/Telegram как **второй** фактор ещё не реализованы; это A6.3m.6, отдельный от существующих основных методов входа.

### Предыдущая приёмка предикатов — A6.3m.1a

`TestMFARequirementPredicatesSchema` проверяет все восемь permissions и обычное продуктовое permission, system administrator, объединение/отзыв ролей и invoker ACL. Существующие SQL-сценарии подтвердили сохранение административного login, MFA status/disable, длительностей сессий и platform/project readiness. Luna V1: task check, targeted race и полный Linux ARM64 TestPrepareCommandSQL — PASS. После исправления параметризованных multi-statement запросов в новом fixture Luna V2 подтвердила targeted lint (0 issues) и все шесть schema-тестов в штатном query mode. Все шесть source hashes совпали со снимком и рабочими файлами; временные стенды удалены.
