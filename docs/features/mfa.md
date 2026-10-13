# MFA: TOTP и резервные коды

## Текущее состояние

A5.2b-local подключает MFA к password, Google/Telegram OIDC и email OTP, App, HTTP и Swagger. A5.2c-local добавляет opt-in email proof для external-only с уже verified owned contact. Для password-account по-прежнему нужен password proof: email не снижает его защиту. Первичная безопасная привязка контакта не опубликована; новый external-only пользователь без проверенной почты этим API воспользоваться не может. Полный A5 и release acceptance не закрыты.

Без подключённого фактора обычный login сохраняется. При enabled TOTP основной вход возвращает HTTP 202, `status=mfa_required`, `challenge`, `expiresAt` и HttpOnly browser cookie, но не новую session cookie. Старую cookie этого браузера очищаем; это не глобальный logout других сессий. После второго фактора создаётся общая SQL-сессия. MFA не заменяет email verification, permissions или основной вход. Factor state нельзя включать/выключать прямым SQL вместо protected flow.

## Настройки и HTTP

| ENV | По умолчанию | Назначение |
| --- | --- | --- |
| `MFA_ENABLED` | `false` | Подключение workflow/routes. Startup с false при уже enrolled factors запрещён; это не обход MFA |
| `MFA_ISSUER` | `Auth` | Имя установки в authenticator |
| `MFA_LOGIN_CHALLENGE_TTL` | `5m` | Срок challenge, допустимо 1m–5m |
| `MFA_USER_OPERATIONS_PER_MINUTE` | `5` | Общий operational admission пользователя для management, primary challenge start и completion |
| `MFA_IP_OPERATIONS_PER_MINUTE` | `10` | IP admission для start/complete login challenge |
| `MFA_PROJECT_OPERATIONS_PER_MINUTE` | `500` | Общий budget установки для start/complete и management вместе |
| `EMAIL_REAUTHENTICATION_ENABLED` | `false` | Подтверждение управления MFA на проверенную почту external-only аккаунта; требует MFA_ENABLED, не включает email login |

Это бюджеты в минуту, не RPS; минимальный budget — два обращения для start+complete, меньший отклоняется конфигурацией. User/project counters общие для management и login, IP — для start+complete. Более высокие budgets не повышают security budget: login factor — максимум пять обращений на пользователя в минуту независимо от замены challenge; pair token+binding тоже ограничена пятью. Step-up имеет отдельный максимум пяти обращений на пользователя в минуту. SQL attempts/challenge — самостоятельная гарантия. Indexed owner lookup для account admission выполняется до транзакции; внутри неё challenge повторно проверяется. Под SQL row lock нет Redis-вызовов. Все ENV должны быть согласованы между экземплярами; сохраняемые настройки относятся к A6.

| Метод и путь после `/api/v1/auth` | Сценарий |
| --- | --- |
| `POST /mfa/login/complete` | JSON `{challenge, code, recovery}` + cookie `__Host-mfa-login`; после commit выдаётся session cookie |
| `POST /mfa/totp/enrollment` | Текущая session cookie + password proof; возвращает pending token, secret, URI и expiry |
| `POST /mfa/totp/enrollment/confirm` | JSON `{token, code}`; включает TOTP, один раз отдаёт десять recovery codes, отзывает sessions |
| `POST /mfa/step-up` | JSON `{code, recovery}` + свежий password proof; подтверждает MFA и ротирует session token без продления lifetime |
| `POST /mfa/totp/replacement` | Свежие password/MFA proofs; новый pending factor, старый работает до confirm |
| `POST /mfa/totp/replacement/confirm` | JSON `{token, code}` от нового фактора; заменяет фактор/recovery codes и отзывает sessions |
| `DELETE /mfa/totp` | Свежие password/MFA proofs; удаляет фактор/codes, отзывает sessions; admin policy может запретить |
| `POST /mfa/recovery-codes/regenerate` | Свежие password/MFA proofs; один раз отдаёт десять новых codes, отзывает sessions/challenges; TOTP сохраняется |

Owner UUID/hash/auth_version берутся из SQL-validated session context, не из JSON. Completion не требует ordinary session: его authority — primary challenge и browser binding. Все mutations требуют allowed HTTPS Origin; GET/link не выполняет действие. Cookies — Secure, HttpOnly, SameSite=Lax, `__Host-`, Path=/ без Domain. Secrets передаются в JSON owner response под no-store, не в URL; duplicates/missing binding отклоняются. Ошибки: `invalid_json`/`invalid_mfa` 400; `unauthorized` 401; `fresh_auth_required`/`mfa_required_by_policy`/`invalid_origin` 403; `mfa_conflict` 409; `rate_limited` 429 с Retry-After 60; dependency failure 503. При отказе session cookie не выдаётся и не ротируется.

Password flow: войти → `POST /reauthenticate/password` → enrollment start → первый TOTP → сохранить recovery codes → войти снова → завершить challenge следующим TOTP/recovery. Первый код уже потреблён: в login использовать следующий 30-second code либо recovery. Recovery не заменяет основной пароль. Для management не повторять ещё свежие proofs; иначе password reauthentication, затем step-up новым TOTP/recovery.

Замена/отключение/перевыпуск повышают auth_version, отзывают sessions и удаляют pending MFA challenges/enrollment атомарно. При потерянном успешном response plaintext codes перечитать нельзя: снова primary+MFA и protected regeneration. Если потеряны устройство и все codes, обычный reset MFA не снимает; operator lost-factor recovery ещё не реализован.

SQL mutations Access требуют password/MFA proofs не старше пяти минут и current factor. Владельцу system super_admin либо permissions `access.roles.manage`/`access.assignments.manage` отключение MFA запрещено даже при backup administrator. Disable берёт общий Access advisory lock до user/session locks; current roles читаются после ожидания, role change не обходит policy гонкой. Динамические required-MFA правила других ролей — A6. Public admin users/roles API ещё не опубликован; Account status/delete остаются trusted-caller workflows до отдельной авторизации transport.

Google/Telegram-only management доступен только с opt-in email proof на уже проверенную почту. Возраст session/callback не заменяет подтверждение. Password-account может применять MFA при Google/Telegram/email OTP login. Completion повторно проверяет enabled policy подключённого метода; runtime settings — A6.

## Подтверждение управления MFA по почте: A5.2c-local

Нужны `MFA_ENABLED=true` и `EMAIL_REAUTHENTICATION_ENABLED=true`. `EMAIL_OTP_ENABLED` независимо управляет passwordless login и может оставаться false. Это не второй способ входа, не verification нового адреса и не восстановление потерянного MFA. В таблице MFA routes выше password proof заменяется email proof только для external-only; проверка existing MFA и administrative disable policy сохраняются.

1. Войти через Google/Telegram и завершить уже подключённый MFA, если он есть.
2. `POST /api/v1/auth/reauthenticate/email/request`, session cookie и JSON `{"email":"already-verified@example.test"}`. SQL проверяет verified owned contact, active/nondeleted user, current version/live session, linked identity, отсутствие permanent/temporary password и pending provision. HTTP 202 устанавливает `__Host-email-reauthentication`; письмо содержит восьмизначный код с назначением «подтверждение управления MFA». Адрес не добавляется к аккаунту.
3. `POST /api/v1/auth/reauthenticate/email/confirm`, JSON `{"code":"12345678"}`, прежняя session cookie и flow cookie. Owner/version/session hash/purpose проверяются заново. Успех атомарно потребляет код, ротирует текущий token, сохраняет email proof и audit; flow cookie очищается, JSON отдаёт `verifiedAt`. Сессия не создаётся заново, idle/absolute expiry и primary/MFA timestamps не продлеваются; password_verified_at не выставляется. Proof действует пять минут и хранит UUID проверенного адреса.
4. Для первого enrollment использовать `/mfa/totp/enrollment` и `/confirm`. Для replace/disable/recovery regeneration требуется также свежий MFA: если старый, вызвать `/mfa/step-up` новым TOTP/recovery. Email proof не доказывает владение вторым фактором. Factor mutations повышают version и отзывают sessions как прежде.

Код не подходит для `/email-otp/confirm`: разные digest purposes, cookie names и SQL purpose/session binding. Logout/rotation после запроса, version/status/contact change и expiry отклоняют confirm. Неверные попытки коммитятся: максимум пять/challenge и пять подтверждений/user/minute независимо от reissue. Request — три/user и три/email за 15 минут плюс cooldown и IP/project budgets. TTL/resend/project limits переиспользуют `EMAIL_OTP_*`; counters email/IP/project общие с email login. Redis вызывается до SQL locks и fail-closed.

Переиспользуются encrypted email outbox, delivery runner и indexed retention — без новой очереди/pool/worker/dependency. Ошибка аудита откатывает rotation/consumption/proof. Обычная проверка сессии не получает нового SQL round trip. Email UUID — authentication snapshot; management повторно проверяет актуальные ownership/verification. Отключение EMAIL_REAUTHENTICATION_ENABLED лишает ещё свежий email proof полномочий. Password-account не может заменить password proof этим flow, Access administrative mutations пока сохраняют password + MFA gate; email proof не выдаёт permissions.

Ошибки новых routes используют общий email OTP/MFA mapper: `invalid_json`, `invalid_email`, `invalid_email_login` 400 (последний — invalid/expired/replayed code); `unauthorized` 401; `fresh_auth_required`/`invalid_origin` 403; `rate_limited` 429; `temporarily_unavailable` 503. Неуспешный запрос не меняет cookies.

**Открытая граница:** первичная безопасная привязка контакта — A5.2d вместе с protected users/operator workflow: отдельно доказать account authority и mailbox ownership. Не добавлять verified contact прямым SQL, не принимать verified=true от UI и не объединять аккаунты по provider email. SQL fixtures используют синтетические заранее проверенные контакты, а не реализованный onboarding. Пока нет такого контакта, external-only enrollment/management закрыты.

## Ограничение повторного входа через провайдера

Проверено 13 октября 2026: обычный новый OIDC callback не даёт права подключать или менять MFA у аккаунта без пароля. `iat` — время выдачи токена, не повторного подтверждения личности; текущий `PrimaryProof.VerifiedAt` отмечает проверку основного login адаптером, а не новое введение credentials у провайдера. Этот proof используется для login challenge, но не заменяет management proof.

- [Google Security bundle](https://developers.google.com/identity/siwg/security-bundle#authentication_time) прямо указывает, что Google Account reauth requests не поддерживаются. Подписанный `auth_time` можно запросить через `claims`, но требуется включить Session age claims в настройках проверенного OAuth app; поле может отсутствовать или отражать старый вход. Новый consent/account chooser не обновляет доказательство аутентификации. Нельзя считать отправку `prompt=login` или `max_age=0` достаточной гарантией для Google.
- [Telegram OIDC](https://core.telegram.org/bots/telegram-login#openid-connect) документирует `sub`, `iss`, `iat`, `exp`, но проверяемая гарантия fresh reauthentication через `auth_time`/`max_age` не подтверждена. Это ограничение имеющихся сведений, не утверждение, что Telegram никогда не поддержит такой сценарий. Нельзя подменять authentication time значением `iat` или временем callback.
- [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) описывает `max_age` и `auth_time`; сам стандарт не подтверждает поддержку каждой возможности конкретным провайдером.

По согласованию выбран отдельный одноразовый email proof для management, реализованный в A5.2c-local выше. Passwordless email login не расширяется на external-only; без предварительно verified owned contact операции закрыты. Provider-specific auth_time flow не реализуется как параллельная замена/fallback. Первое безопасное добавление контакта остаётся A5.2d.

## Внутренний вход с MFA: A5.2a-local

`service.Login.Start` вызывается только адаптером, уже проверившим основной вход. `PrimaryProof` содержит UUID, auth_version, основной метод и его проверенную ссылку: актуальный password hash после Compare/CAS rehash, OIDC issuer/subject после provider validation либо ID текущего verified email после потребления email OTP. Эти ссылки не являются самостоятельным доказательством; контракт запрещено заполнять из JSON/query/headers. Session login coordinator подключён к method adapters: обычная SQL issuance либо challenge по `ErrMFARequired`, без обхода через другой метод.

SQL проверяет active/nondeleted account и auth_version под user lock, затем сверяет current credentials/identity/email. Основное доказательство должно быть не старше минуты. Допускается до пяти секунд рассинхронизации backend/DB; при опережении backend сохранённое время ограничивается SQL statement timestamp, будущий authentication time не записывается. Часы должны синхронизироваться. Для email OTP сохраняются ограничения существующего метода: verified текущий email постоянных credentials, без pending provisioning/temporary password. Наличие enabled TOTP обязательно; Start не заменяет регистрацию или обычный вход.

Создаются два независимых случайных значения по 256 бит: challenge token и browser binding. SQL хранит scoped keyed digests, не plaintext. Token передаётся в POST body, binding — в Secure/HttpOnly cookie. Один pending challenge/user с TTL до пяти минут. Новый проверенный primary login заменяет старый challenge, не создаёт сессию и не меняет фактор. В audit не попадают tokens, binding, password hash или OTP.

`Login.Complete` принимает token/binding/код, но не пользовательский UUID, auth_version или MFA timestamp. Владелец берётся из SQL challenge. Порядок блокировок — user → challenge → factor → session; первый digest/binding lookup не блокирует строку. После ожидания user lock отдельный запрос заново проверяет challenge, expiry/attempts/version и исходные credentials. Отзыв/смена credentials или identity, block/delete/version change делают challenge непригодным.

Правильный TOTP/recovery, его потребление, две audit-записи, удаление challenge и INSERT в общую `auth.sessions` коммитятся одной транзакцией. Сбой сессии или audit откатывает всё, включая recovery verifier/TOTP step; raw session token возвращается только после успешного commit. У одного challenge один победитель. Неправильный код коммитит SQL attempts до возврата общей ошибки; максимум пять. Ошибочная browser binding не расходует SQL attempts владельца. Redis completion budget привязан к паре token+binding, поэтому знание одного token не позволяет расходовать бюджет настоящего браузера.

`LoginConfig` получает явные положительные user/IP/project budgets и TTL из проверенных ENV. Start/Complete имеют отдельные Redis namespaces, fail-closed и timeout пять секунд; pair/account security counters не растут вслед за operational budgets. IP/User-Agent и tokens ограничены до зависимостей. Дополнительных pools/workers/dependencies нет; сохраняемые настройки остаются A6.

MFA-сессия хранит `primary_method`, `primary_verified_at` и `mfa_verified_at`. PostgreSQL задаёт время второго фактора; middleware читает context/auth_version тем же SQL session lookup, не из header. Refresh/rotation/password reauthentication не обновляют MFA freshness. Обновление MFA времени возможно только через protected factor consumption и rotation. У обычных/старых сессий nullable MFA proof отсутствует, они не получают его автоматически. SQL constraint допускает step-up после создания session, сохраняя порядок primary/MFA и absolute deadline.

Expired challenges очищаются existing bounded retention по expiry index, удаление аккаунта удаляет pending challenge. Reset/version change инвалидируют его логически; сброс пароля не снимает фактор. Ошибка или потеря успешного ответа не позволяют повторно получить использованную сессию: пользователь начинает новый основной вход.

## Подключение фактора

Внутренний `StartEnrollment` получает user UUID, hash текущей сессии и ожидаемую auth_version. Репозиторий проверяет active/nondeleted account, live session/current version и primary proof не старше пяти минут: password либо opt-in verified-email proof для external-only по A5.2c. Actor/user ID сами по себе не являются доказательством; новый адрес без ownership verification этим сценарием не добавляется.

Создаются новый случайный секрет 32 байта, manual key, `otpauth` URI для будущего QR и enrollment token 256 бит. В URI issuer задаёт установка, account label — стабильный UUID, не выдуманный email. Профиль — шесть цифр, 30 секунд, HMAC-SHA1; совместим с обычными TOTP authenticators и не зависит от Google/Gmail login. Используется [pquerna/otp v1.5.0](https://github.com/pquerna/otp/tree/v1.5.0), а не собственная реализация OTP. Параметры и replay policy сверены с [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).

Секрет шифруется существующим AES-GCM Cipher с purpose `mfa:v1` и owner UUID. Перестановка ciphertext между пользователями отклоняется. App передаёт scoped cipher из существующего operational encryption key; новый root key/pool/worker не создаётся, реальные ключи этим шагом не меняются.

Pending enrollment один на пользователя, срок — десять минут, максимум пять неправильных кодов. Повторный start заменяет pending secret/token, но не действующий фактор. Ошибочная попытка подтверждения коммитит счётчик перед возвратом ошибки; infrastructure failure откатывает операцию. Enrollment привязан к той же session hash/auth_version: logout, rotation, block или version change лишают его полномочий. Уже включённый фактор нельзя перезаписать этим сценарием.

`ConfirmEnrollment` заново проверяет свежую сессию и token, валидирует первый код по времени PostgreSQL, затем одной транзакцией сохраняет фактор/использованный time step, десять recovery verifiers, увеличивает auth_version, отзывает все прежние сессии, удаляет pending enrollment и записывает audit. Сбой audit откатывает всё. Ни сессия, ни административные права не выдаются.

Manual key/URI/enrollment token и plaintext recovery codes исключены из автоматической сериализации внутренних результатов; HTTP DTO отдаёт их явно только владельцу под no-store. Их нельзя логировать, помещать в URL или telemetry. Codes возвращаются только после commit и не перечитываются; regeneration требует нового protected proof. Pending enrollment хранит purpose enroll/replace; токены этих сценариев не взаимозаменяемы.

## Проверка и одноразовость

Внутренний `Verify` — trusted-caller primitive: user UUID/auth_version должны происходить из подтверждённого primary/challenge workflow, не из клиентского JSON. Это проверка и потребление фактора, не самостоятельный login endpoint или переносимый authentication ticket. Возвращённое время нельзя передать обратно как клиентское доказательство.

SQL заново проверяет active/nondeleted пользователя и текущую auth_version, блокирует user перед factor. TOTP допускает только текущий и соседние time steps (±30 секунд). Все кандидаты проверяются, сохраняется наибольший совпавший step; использованный или более старый step повторно не принимается. Браузер не выбирает timestamp. Нужны синхронизированные часы PostgreSQL/устройства; откат часов не сбрасывает защиту replay.

Десять резервных кодов имеют по 128 случайных бит, формат — 32 lowercase hex-символа. SQL хранит только owner-bound keyed SHA-256 verifiers. Успешный recovery удаляет ровно свой verifier и пишет audit в той же транзакции; один код имеет одного победителя даже при параллельных запросах. Отказ аудита сохраняет код для явного повторения. Recovery code не заменяет primary login, не отключает MFA, не меняет password/status/роль и не создаёт сессию.

Management Redis admission выполняется до SQL и fail-closed, budgets указаны выше. Unit/SQL fixtures используют разрешающий limiter для проверки SQL-конкуренции; отдельный live Redis 8.2 test подтверждает atomic counter, TTL, независимость keys и ошибку закрытого клиента. Это не полная Redis outage/mixed-load acceptance.

## Сессии и lifecycle

Общий PostgreSQL `CreateSession` после user lock/current version check выполняет один дополнительный PK-based EXISTS для active TOTP. Если фактор есть, возвращает `session/domain.ErrMFARequired` без INSERT. Все существующие primary methods используют эту выдачу, поэтому сменой password на OIDC/email OTP обойти фактор нельзя. Отдельный запрос после ожидания блокировки и explicit Read Committed исключают устаревший снимок enrollment. Фактор не кешируется; роль Redis в остальных сценариях не меняется. Session cache этим шагом не добавляется.

После отдельного `Verify` этот запрет тоже остаётся: открывать его boolean-полем или клиентским timestamp нельзя. A5.2a-local связывает primary proof, browser challenge, factor consumption и session context атомарно через `Login.Complete`; самостоятельный Verify не выдаёт login authority. `consumeFactor` переиспользуется без копирования OTP/recovery логики.

Password reset/change и защитное account recovery не удаляют фактор. Удаление аккаунта очищает pending/enabled secrets и recovery verifiers; audit сохраняется по общей политике. Existing retention worker удаляет expired enrollment индексируемыми bounded batches и MFA audit через SECURITY_AUDIT_RETENTION_DAYS, по умолчанию 180 дней. У модуля нет собственного polling loop или goroutine.

## Открытые части A5

- Первичная безопасная привязка контакта external-only аккаунту, required MFA по ролям, безопасный first-admin setup и отдельный lost-factor процесс.
- Public admin users/roles transport с permissions/fresh-auth/MFA, runtime settings A6 и UI A7; internal SQL role mutations уже защищены.
- Browser/live authenticator/provider, Redis/SQL faults и mixed load/restore acceptance; локальные HTTP/SQL/Redis checks не заменяют release gates A8.
- SMS после выбора provider; passkeys вне текущего выпуска.

Расширена только исходная `000001_init`: mfa_totp, mfa_enrollments, mfa_login_challenges, mfa_recovery_codes, mfa_audit и nullable session authentication context. Уже применённой установке нужен отдельно согласованный upgrade, не reset или повторный migrate up. Рабочая БД/secrets/env не изменялись.
