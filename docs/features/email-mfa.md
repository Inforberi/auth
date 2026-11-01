# Email как дополнительный фактор

Подготовка канала, управление, внутренний вход/recovery и проектная сборка/deployment .6c.1–.4b.3 проверены Луной. Email MFA доступен через явный project opt-in и отдельное разрешение политики/выбор пользователя; по умолчанию выключен. Standalone/platform email MFA не включён. Локальная приёмка .4b завершена после Luna V2 .4b.4; внешние release gates отдельно: [матрица покрытия](../operations/acceptance-summary.md#сверка-email-mfa-4b--1-ноября-2026). Разделы .6c.1–.4a ниже описывают отдельные шаги реализации; прежние ограничения подключения в них относятся к дате шага и заменены проектной сборкой .4b.2–.3.

## Сценарии и границы

| Сценарий | Входные гарантии | Результат |
| --- | --- | --- |
| Подготовка канала — этот подэтап | Текущая browser/password session, explicit password proof моложе5m, уже подтверждённый принадлежащий пользователю email; строгий TOTP/recovery, если текущая policy/personal factor требует MFA | Почтовой possession proof и ротация существующего session token с прежними ID/сроками/primary/password/MFA proofs. Не новый вход/роль/фактор |
| Активация и выбор — внутренний .6c.2, Luna PASS | Актуальные права/политика, осознанное включение, подготовленный канал, допустимый primary/factor pair | Сохранённая привязка к контакту и отзыв credentials; публичное включение закрыто до полного enforcement |
| Email MFA login — внутренний .6c.3, Luna PASS | Подтверждённый primary, bound challenge, разрешённый активный фактор/канал, одноразовый код | Consume+session/native issuance в одной transaction с явным слабым методом; не TOTP/strict authority |

Первый компонент принимает только password primary. Email OTP и OIDC не допускаются: дополнительный код после email primary нельзя назвать независимой MFA; для внешнего provider нужна отдельно согласованная policy независимости канала. API/native session не принимается. Подтверждённый контакт сам по себе не означает согласие включить MFA.

## Подготовка канала

`service.NewEmailPreparation(repo,cipher,limits,tokens,cfg)` получает project-scoped email-login cipher/Redis limiter, не чужой default secret. Config задаёт TTL1..5m, resend interval1s..<TTL и положительные project request/confirm budgets. Сборка в startup/project profiles пока закрыта до следующих подэтапов: этот компонент не создаёт новый публичный способ входа.

`Request(ctx,proof,email,ip)` берёт proof из доверенного текущего session context, не из произвольного JSON. Domain один раз нормализует email. SQL под Access snapshot/user/session/password locks проверяет пользователя/version/status, browser/password primary, explicit password freshness, текущую строгую MFA при необходимости, отсутствие temporary/pending provisioning и принадлежность verified email. Чужой/неподтверждённый адрес не создаёт outbox. Фиксируются email ID, auth_version и исходный session hash. Deadline ограничен TTL, session/password/MFA freshness и перепроверяется перед commit.

Код — восемь случайных цифр, binding —256bit; наружу коду не возвращается plaintext OTP. Verifier/digest имеют отдельный prefix `mfa-email-prepare:`, challenge purpose=`mfa_email_prepare`; encrypted payload использует существующий email-login cipher и JSON to/subject/body. Challenge/outbox/audit создаются атомарно. Resend заменяет только это назначение и не продлевает account-wide guessing budgets.

`Confirm(ctx,EmailPreparationConfirmation)` повторно проверяет текущую session/права канала/version/freshness и точное назначение. Пять неверных попыток коммитятся и удаляют отработавший outbox, не откатываются с публичной ошибкой. Успех потребляет code один раз, ротирует только исходный session token и записывает email_reauthenticated_id/at. Возвращается новый token текущей session, а не новый login; MFA method/time, password proof, роли/auth_version и сроки не повышаются. Другой session того же пользователя не может подтвердить intent. Audit/SQL failure откатывает rotation/consume вместе; повтор со старой cookie/перенесённый код не даёт authority.

Этот email possession proof — предпосылка будущей активации, не её выполнение. TOTP/recovery и RequireStrongMFA для критических операций сохраняются. Если текущая MFA policy не требует фактора и его нет, свежий парольный пользователь может подготовить канал, но это не включает MFA незаметно.

## Переиспользование и нагрузка

Подготовка переиспользует существующие email_login_challenges/outbox/audit без отдельного worker/очереди; привязка фактора хранится в auth.mfa_email (.6c.2). UNIQUE(user_id,purpose) ограничивает pending intents одним на назначение; native/browser primary login по-прежнему заменяют одно общее login intent. Legacy request удаляет только свой purpose. Security revocation/reset/retention по-прежнему могут удалить все intents пользователя. Target tuple immutable, ownership FK и expiry/lease indexes сохранены.

Delivery проверяет актуальность канала/source session/password/строгой MFA на своей ветке и использует прежний sender, lease/retry/expiry cleanup. Нет keyspace scans, горячих full-table проходов или синхронной SMTP в request. Redis budgets purpose/user/IP/project; ошибки admission fail-closed. Перед HTTP подключением понадобятся profile readiness/route/CSRF/source-cookie и реальные scoped Redis приёмки — этот срез их не объявляет проверенными.

Schema меняется в исходной prerelease migration; реальные DB/ENV не менялись, upgrade существующей БД отдельно MP6. Подготовлены unit crypto/admission и TestEmailFactorPreparationSchema: purpose coexistence, owned channel, no authority/lifetime increase, one-winner/replay/attempts, stale/revoked/unverified/primary/native guards и audit rollback. Luna: task check, emailotp race, TestEmailFactorPreparationSchema, TestPostgresSchema и TestTwoProjectEmailOTPHTTPIsolationSQL — PASS; manifest 24/24, тестовый стенд очищен.

## Внутреннее управление — A6.3m.6c.2

Разрешение проекта и выбор пользователя разделены. Новая колонка `auth.mfa_settings.email_factor_allowed` по умолчанию false; режим optional/administrators/required остаётся в действующей MFA policy. `settings/service.EmailMFA` читает и изменяет разрешение с тем же version, что и режим MFA: параллельное изменение любого из них требует перечитать настройки. Read/update заново проверяют `auth.settings.manage`, пользователя, session и свежие proofs. Update использует Access exclusive lock и финальный deadline, сохраняет non-secret audit. Включение требует trusted assembly readiness, передать её через запрос нельзя. Отключение запрещено, пока есть хоть одна привязка, включая приостановленную: без массового обхода пользователей, снятия защиты или автоматического fallback.

`mfa/service.EmailFactors` предоставляет внутренние Status/Enable/Disable. Enable не принимает user ID/email/method из DTO как готовую authority: Proof связывается с актуальной browser/password session, текущими credentials и version. Нужны свежий явный password proof и email possession proof той же session на verified owned contact; при действующей защите также свежий proof допустимого текущего фактора. Когда настроен TOTP, принимается TOTP/recovery; для email-only используется явно записанный email proof. Сроки перепроверяются перед commit. Нормализация адреса уже выполнена при подготовке, повторной domain-валидации здесь нет. Mutation admission использует project-scoped MFA cipher/limiter, errors fail-closed.

`auth.mfa_email` хранит одну привязку пользователя к конкретному email ID, enabled_at и nullable suspended_at. FK проверяет принадлежность контакта, привязка не зависит от TOTP row и не исчезает при изменении общего режима. Enable/Disable атомарно меняют auth_version, отзывают все SQL/browser/native sessions, удаляют pending MFA/email OTP challenges и записывают audit. Новую session или MFA proof они не выдают; новый вход нужен даже после успешного изменения. Два конкурентных Enable с одной исходной session дают один успех. Повтор активного Enable с новым доказательством возвращает conflict; приостановленную привязку можно подготовить и включить заново.

Status различает Allowed, Configured и Usable. Последнее означает только разрешённый, неподвешенный verified канал; не готовность runtime и не выданный MFA proof. Read проверяет актуальную session/version/status пользователя, но не требует свежих proofs изменения.

Смена email, security report и protected recovery приостанавливают прежнюю привязку в существующей транзакции инвалидирования доступа и сохраняют audit. Новый verified email не наследует второй фактор. Неподтверждённый/приостановленный контакт не считается пригодным каналом, однако сам факт настроенного фактора продолжает требовать MFA: нельзя получить password-only доступ из-за потери почты или optional policy. Block/unblock сохраняет привязку и отзывает credentials; удаление аккаунта очищает её. Смена/reset пароля не удаляют независимо настроенный фактор. Recovery потерянного email-only фактора ещё не опубликован.

**Закрытый gate:** startup/project profiles, HTTP и новые ENV не подключены. CheckCapability отказывает runtime с разрешённым email MFA или привязками до полной приёмки .6c.4. Правила .6c.3 позволяют убрать email-only фактор при optional policy после свежего password/email proof; при обязательности последний фактор не удаляется. Для обычного аккаунта удаление TOTP допускается, если остаётся пригодный email-фактор; suspended/непригодный канал не является заменой. Для административного аккаунта email-only конфигурация пока закрыта: включение требует существующий TOTP, его удаление при email binding запрещено до admin/profile compatibility gate .6c.4. Optional политика сама по себе не требует включать MFA. TOTP/recovery management и другие строгие операции по-прежнему требуют strong proof. Это не автоматическое ослабление политики при потере фактора.

Подготовлены unit fail-closed admission и SQL `TestEmailFactorLifecycleSchema`: shared version/permissions/readiness, one-winner активации, отзыв sessions, независимость TOTP, policy/activation race, optional email-only без обхода, block/unverify, stale/missing mail proof, audit rollback, реальная смена email и удаление. Luna: task check, affected race и пять назначенных SQL roots — PASS; manifest 25/25, cleanup подтверждён. Новых зависимостей/воркеров/публичных маршрутов нет. Исходные up/down изменены без отдельной лишней migration; реальный upgrade остаётся MP6.

## Внутренний вход и восстановление — A6.3m.6c.3

`emailotp/service.EmailLogin` принимает доверенный результат проверки пароля и явно выбирает email как второй фактор. Start/StartNative проверяют форму primary proof и IP, project/user/IP admission и cooldown отправки; SQL повторно проверяет актуальные password credentials, active user/auth_version, включённый метод, verified owned binding без suspension и отсутствие temporary/pending provisioning. Административный primary proof, OIDC и email-primary в этот компонент не допускаются. Наличие роли само не меняет метод подтверждения: строгие действия отдельно проверяют strong proof.

В existing `mfa_login_challenges` сохраняются выбранный factor_method, конкретный email ID и прежние primary/browser/native/audience/scope/policy revision bindings. Новое назначение `mfa_email_login` в existing OTP ledger связано FK с parent MFA digest; code/outbox создаются вместе с parent intent. Один пользователь имеет один актуальный parent intent. Новый primary очищает прежний email-code intent и recovery candidate до замены parent digest. Код — 8 случайных цифр; raw OTP возвращается только через encrypted mail payload. Для parent token/browser/native binding и code verifier используются отдельные purpose prefixes и project-scoped MFA/mail keys. Nonce не является доказательством успешной MFA.

Complete проверяет token+browser binding и code, действующие proof/channel/policy/version/profile, сопоставляет verifier constant-time под user/parent/code locks. Пять ошибочных попыток сохраняются в обоих связанных counters; отработавший outbox убирается. Admission на пользователя общий с TOTP factor guessing и не сбрасывается заменой challenge. Native scope/audience читаются из bound parent и заново авторизуются перед выдачей. Browser, native, старый email-primary и TOTP completion не взаимозаменяемы.

Правильный код выдаёт browser session либо native session/refresh family/access JWT в одной транзакции с consume и audit. Подписание/аудит/SQL failure откатывают выдачу и потребление, повтор возможен только пока intent действителен. Финальный SQL clock deadline проверяется после аудита. FK удаляет оставшийся code/outbox при consume/expiry/revocation родителя. SMTP остаётся асинхронным existing worker; delivery заново проверяет текущий parent/password/binding/policy, попытки, профиль и сроки.

Session сохраняет `mfa_method=email` и время. Access/refresh/exchange сохраняют `amr=[pwd,email_otp]`; primary `emailotp` — другой метод. JWT parser принимает email_otp только вместе с pwd и mfa_time. Introspection требует точного совпадения с актуальным SQL proof, usable channel и session authority. `strong_mfa_verified_at` остаётся NULL, RequireStrongMFA и SQL critical actions не принимают email вместо TOTP/recovery. Local JWT имеет прежнее окно отзыва до TTL; мгновенная проверка использует strict introspection/SQL.

Для повторного подтверждения email используется та же полная password→email-code цепочка с новой session. Fresh password proof для управления фактором получается через существующее explicit password reauthentication; обычный вход не подделывает этот private proof и не увеличивает его давность. Добавление первого TOTP при уже включённом email-факторе также требует свежего текущего email proof; старую cookie с одним повторно введённым паролем нельзя превратить в новый strong фактор.

### Потеря почты

Если остаётся TOTP/recovery, применяется существующий strong вход/управление. Если email был единственным фактором, обычный primary challenge помечается RecoveryRequired/assisted_recovery: он не выдаёт сессию и не открывает first-TOTP enrollment. Через существующий browser recovery пользователь задаёт новый TOTP, выделенный DB operator отдельно одобряет конкретный request/version/environment/reason. Runtime не может сам одобрить запрос. Завершение требует правильный код нового TOTP и действующее одобрение текущего уполномоченного оператора; создаёт TOTP/recovery codes, удаляет потерянную email-привязку, увеличивает auth_version, отзывает credentials и сохраняет аудит/уведомление атомарно. Новая session автоматически не выдаётся. Native приложение проходит это восстановление через browser flow, затем выполняет обычный вход.

Configured binding учитывается для assisted recovery даже при suspension/утрате verified канала: именно потерянный канал восстанавливается. Его usability требуется для email-кода входа, но не заменяет независимое password+operator+new-TOTP approval. Сам пароль, email-verify или password reset не снимают MFA; обычный password reset сохраняет enrolled factor. Потеря одновременно пароля и почты требует существующего отдельного операторского/offline процесса, а не policy toggle.

Подготовлены `TestEmailFactorLoginSchema` (browser/native one-winner, profile/purpose/factor immutability, JWT/introspection/refresh, fail-closed guards, attempts, audit rollback, last-factor и TOTP transitions) и `TestEmailFactorRecoverySchema` (suspended email-only, operator separation/approval, rollback, замена на TOTP и повторный вход). Unit admission и JWT tests проверяют dependent primaries и отсутствие strong elevation. Luna V3: task check и четыре SQL roots с race PASS; V2 token service race и пять успешных SQL roots V1 сохранены без повторения. Manifest 48/48 и cleanup подтверждены. Публичных маршрутов, нового worker/dependency/ENV и реальных DB изменений нет.

## HTTP-адаптеры — A6.3m.6c.4a (Luna PASS)

Контракты transport/http подготовлены в .6c.4a. В .6c.4b.2 ниже добавлена opt-in сборка ProjectProfile и маршруты; Luna V1–V3 checks/race/API/SQL PASS. Standalone/platform email-фактор не включают; deployment opt-in .4b.3 принят после Luna V2; реальные настройки по умолчанию остаются выключенными. Наличие Swagger не означает включённый метод.

| Планируемая ручка | JSON / контекст | Результат |
| --- | --- | --- |
| POST /api/v1/auth/mfa/email/login | email, password; trusted adapter проверяет пароль | 202 challenge/expiresAt, статус email_mfa_required, отдельная HttpOnly binding cookie; полноценная session не создаётся |
| POST /api/v1/auth/mfa/email/login/complete | challenge, code; binding только из одной __Host-mfa-email cookie | 200 ok и session cookie; binding cookie очищена, raw session token не возвращается в JSON |
| POST /api/v1/auth/mfa/email/preparation | email; текущая session proof | 202 binding/expiresAt; кода в JSON нет |
| POST /api/v1/auth/mfa/email/preparation/confirm | binding, code; текущая session proof | 200 ok, ротация cookie текущей session; не включение MFA |
| GET /api/v1/auth/mfa/email | текущая session proof | allowed/configured/usable/emailId/enabledAt/suspendedAt, без token/verifier |
| POST /api/v1/auth/mfa/email | текущая session proof, JSON-параметров authority нет | 200 ok, текущая cookie очищена после успешного revoke |
| DELETE /api/v1/auth/mfa/email | текущая session proof | 200 ok, cookie очищена; policy/last-factor отказ сохраняет cookie |
| GET /api/v1/admin/auth/settings/mfa/email | principal из текущей session, SQL permissions | version/allowed |
| POST /api/v1/admin/auth/settings/mfa/email | expectedVersion, обязательный allowed (false допустим); principal из context | version/allowed либо version/readiness/in-use conflict |

Browser-привязка Secure/HttpOnly/SameSite=Lax/Path=/, без Domain; дубли cookie отклоняются до completion service. JSON binding для browser login, UUID/actor/version/capability вне описанных DTO отклоняются декодером. Owner actions используют только request context, не параметры target user. Все ответы, в том числе ошибки, no-store; ошибки политики/лимитов/фактора переводятся существующим httpx mapper с локальными правилами. Domain-проверки email/password/code остаются в service/domain. Origin/CSRF и NoRefreshAuth принадлежат route middleware: unit контракт использует existing RequireOrigin, реальный защищённый router проверяется в .6c.4b.

NewEmail требует сразу password/login/preparation/factor services; сборка частичного handler не допускается. Это ещё не SMTP/profile readiness: приложение пока этот constructor не вызывает. Новых runtime flags, маршрутов, schema, зависимостей и worker в .6c.4a нет. Native method selection должен создавать именно bound MFA challenge: выбранный email-вариант не должен незаметно выдать plain credentials через обычный NativeLogin.Begin. Его сборка, recovery next-step response и project cookie rewriting — .6c.4b.

Luna: task check и race для MFA/settings HTTP — PASS, manifest 19/19, временные проверочные caches очищены. SQL/Docker для transport-only изменения не запускались.

## Что остаётся до публикации email MFA

Сборка, method selection, budgets, browser/native HTTP/Swagger и межпроектные guards приняты в .4b.1–.3. Успешные expiry/concurrency/role/strong проверки не повторяются ради другой формы запуска. Полное покрытие и evidence — в [матрице .4b](../operations/acceptance-summary.md#сверка-email-mfa-4b--1-ноября-2026).

Оба оставшихся сценария .4b.4 приняты после Luna V2: actual HTTP отказ Redis при завершении browser/native email MFA и восстановление email-only аккаунта без TOTP через независимое одобрение. Локальная .4b завершена. Внешняя SMTP/браузерная приёмка и общий release gate отдельно; Telegram-фактор и UI не входят в этот блок.

## Проектная сборка и явный выбор — A6.3m.6c.4b.2

Принято после Luna V3: task check/API/targeted race, email schema roots и actual project SQL/HTTP/Redis PASS с cleanup; evidence — [history](../planning/history.md). `ProjectProfileConfig.EmailMFA` — доверенная operational capability, не JSON-флаг клиента. Требуются browser/password MFA config с RecoveryEnabled, действующие management/recovery factories, project-scoped ключи/Redis, сохранённый SMTP и работающий ProjectDelivery. Проверка recovery отдельно подтверждает NOLOGIN group/grants и отсутствие approval authority у runtime. Фактическую внешнюю SMTP-доставку одна readiness не доказывает.

`ProjectEmailMFAConfig.Preparation` задаёт TTL 1–5 минут, resend interval, RequestsPerMinute/ConfirmationsPerMinute. `Factors` задаёт UserMutationsPerMinute/ProjectMutationsPerMinute (рекомендуемые исходные значения 5/500). Login использует существующие MFA user/IP/project budgets и TTL, с общими guessing counters и отдельным resend cooldown. Значения — попытки за окно, не capacity/RPS. На этапе .4b.2 конфигурация передавалась напрямую сборщику; operational ENV и manifest opt-in добавлены в .4b.3, default остаётся выключенным.

При каждой операции сервис/SQL repository создаются внутри одного project lease. Owner preparation/confirm, Status/Enable/Disable и browser login/complete используют existing services/SQL; новый сервисный контейнер или очередь не вводятся. SMTP-отправка остаётся в общем ProjectDelivery через существующий OTP outbox. На Read/Disable/завершении уже полученного кода сетевой SMTP не требуется; выдача нового письма/Enable защищена delivery gate. При включении project policy дополнительно перепроверяются текущие SMTP credentials и operator/runtime grants; при Read этой проверки нет.

| Метод | Путь | Защита |
| --- | --- | --- |
| POST | `/api/v1/auth/mfa/email/login` | Password primary → email challenge, Origin |
| POST | `/api/v1/auth/mfa/email/login/complete` | Origin + ровно одна проектная binding cookie + challenge/code |
| POST | `/api/v1/auth/mfa/email/preparation` | NoRefresh owner session + свежий отдельный password proof/current factor |
| POST | `/api/v1/auth/mfa/email/preparation/confirm` | Тот же owner/session proof + отдельные binding/code |
| GET / POST / DELETE | `/api/v1/auth/mfa/email` | NoRefresh owner context; Status / Enable / Disable |
| GET / POST | `/api/v1/admin/auth/settings/mfa/email` | Current permission/proofs + version; readiness не принимается из JSON |
| POST / OPTIONS | `/api/v1/auth/native/mfa/email/login` | Cookie-free native password/resource; только bound challenge |
| POST / OPTIONS | `/api/v1/auth/native/mfa/email/complete` | Cookie-free native challenge/binding/code; atomic JWT/refresh/session |

Browser cookie имеет имя `__Host-mfa-email-<project UUID>`: Secure, HttpOnly, Lax, Path=/, без Domain. UUID задаёт backend после выбора проекта по trusted origin; исходная cookie другого проекта/standalone не используется. Подмена имени без соответствующих scoped cryptographic proof не помогает. Общая session cookie и TOTP cookie сохраняют прежний контракт; их crypto/SQL authority остаётся project-scoped. Нового универсального cookie-rewriting middleware нет.

Default password/TOTP endpoints не меняют семантику. Email-only пользователь на обычном MFA пути получает recovery next-step, а для обычного email входа явно выбирает новые endpoints. Native selected-email coordinator вызывает BeginMFA, не plain-first Begin: даже при разрешённой обычной password-only выдаче выбранный вариант не может получить токены без фактора. При потере email native клиент проходит existing browser operator-assisted recovery, затем обычный вход; собственного native bypass/recovery approval нет.

Email primary + email factor не считается независимой MFA и не поддерживается; selected flow принимает только password primary. Email session/JWT сохраняют фактический метод email/email_otp и не становятся strong TOTP/recovery proof. Administrative email login остаётся запрещён: при Channel lookup, transactional start и consume повторно проверяются **текущие** административные права, а не только старый Administrative marker challenge.

Обычную administrative role нельзя назначить email-only пользователю; изменение permissions роли не может сделать таких участников администраторами без TOTP. Проверка использует existing auth.has_administrative_access и общий Access lock в той же транзакции, без нового списка permissions. Super-admin readiness/last-admin guard также не считают email-only достаточным фактором. Сначала подключается TOTP, затем назначаются права; пользователи с TOTP+email сохраняют эту возможность. Ошибка ordinary role transition — conflict, super-admin target — target_unavailable. Повышение роли после выдачи email challenge закрывает его completion даже при неизменённом auth_version.

Старый CheckCapability продолжает запрещать email в standalone/platform. Проектный CheckEmailCapability получает readiness только после полной сборки; при сохранённых email-policy/bindings и отсутствующей capability cold profile отклоняется. Новые handler/config/generation не означают закрытый release gate.

Добавлены unit tests forced-native/no-plain, scoped-cookie, configured budgets/readiness и actual TestTwoProjectEmailMFAHTTP: два проекта/DB/Redis/HTTPS, policy/version, channel preparation, Enable/revoke, replay/cross-profile/cross-project/Origin, native issuance и AMR, role grant/update/last-admin guards, stale challenge после повышения роли, cold-profile fail-closed. Код извлекается только из зашифрованного тестового outbox; успешная внешняя SMTP-доставка этим тестом не доказывается. Deployment/ENV/manifest и проверка границ конфигурации приняты после Luna V2 в .4b.3; оставшиеся границы приёмки перечислены выше и в матрице .4b.

## Включение через deployment — A6.3m.6c.4b.3

В manifest добавлен opt-in `emailMFA` для UUID проекта (browser only), в ENV — отдельные channel/change budgets. Default off; SQL-разрешение и личная привязка не включаются автоматически. Общая конфигурация платформы не меняется, recovery включается только в копиях выбранного project profile. Static prerequisites отклоняют неверный запуск; runtime остаётся fail-closed по Redis/SMTP/delivery/operator-grants. [Настройка и ограничения](project-auth-deployment.md#email-mfa-из-manifest--a63m6c4b3). Новые schema/dependencies/workers не добавлены, внешняя SMTP-доставка не заявляется. Luna V2 task check/race и manifest-backed actual HTTP/SQL/Redis PASS с cleanup. Сводный .4b/release gate оценивается отдельно; внешние SMTP/capacity этим не закрыты.

## Завершение приёмки — A6.3m.6c.4b.4 (PASS Luna)

В TestTwoProjectEmailMFAHTTP добавлен реальный Redis admission fault на completion counter уже выданного browser/native challenge: два безопасных 503, без выдачи credentials/consume/SQL guessing charges; после восстановления счётчика успешный повтор создаёт одну сессию, budget имеет TTL, replay отвергается. Это command/counter fault, не имитация сетевого partition или общий capacity benchmark.

Новый TestTwoProjectEmailMFARecoveryHTTP использует те же deployment/two-project fixtures: suspended email-only без TOTP даёт recovery next-step; missing/foreign binding и completion без approval отклоняются. Runtime не может одобрить заявку; отдельное operator-соединение одобряет, HTTP заменяет email-фактор на TOTP, отзывает старые сессии и выдаёт recovery codes без автоматического входа. Повтор completion запрещён, соседний проект не меняется, последующий вход с новым recovery code работает. Seed lost-mail состояния — setup теста, не новая публичная операция. Runtime/SQL schema/API/dependencies/workers не менялись. Formatter выполнен; Luna V2 task check и оба actual HTTP/SQL/Redis roots с race/count1 PASS без SKIP, manifest8/8 и cleanup подтверждены. V1 compile FAIL исправлен только в operator fixture: existing SQL вызывается через отдельное pgx.Conn; runtime denial использует pool. Локальная .4b завершена, внешний release gate отдельно.
