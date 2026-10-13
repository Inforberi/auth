# MFA: TOTP и резервные коды

## Текущее состояние

A5.1-local и A5.2a-local — проверенный внутренний backend, не готовый публичный вход с MFA. Реализованы enrollment, подтверждение первого TOTP, одноразовое потребление TOTP/recovery, SQL-хранение, ограничения, browser-bound login challenge и атомарное создание общей сессии после второго фактора. Модуль пока не собран в App и не подключён к router: в Swagger нельзя включить MFA пользователю. Полный A5 не закрыт.

Следующие части A5.2 подключат этот workflow к password/OIDC/email OTP, App/HTTP и защищённому управлению фактором. До публикации нельзя вручную включать фактор в рабочей БД: обычная выдача сессии такому аккаунту намеренно закрыта, а публичного completion ещё нет.

## Внутренний вход с MFA: A5.2a-local

`service.Login.Start` вызывается только адаптером, уже проверившим основной вход. `PrimaryProof` содержит UUID, auth_version, основной метод и его проверенную ссылку: password hash после Compare, OIDC issuer/subject после provider validation либо ID текущего verified email после потребления email OTP. Ни UUID, ни hash/identity/email ID сами по себе не являются доказательством: этот внутренний контракт запрещено заполнять из JSON, query или headers. Пока существующие method adapters этот workflow не вызывают; их подключение и проверка effective enabled/verification policy остаются следующим шагом.

SQL проверяет active/nondeleted account и auth_version под user lock, затем сверяет current credentials/identity/email. Основное доказательство должно быть не старше минуты. Допускается до пяти секунд рассинхронизации backend/DB; при опережении backend сохранённое время ограничивается SQL statement timestamp, будущий authentication time не записывается. Часы должны синхронизироваться. Для email OTP сохраняются ограничения существующего метода: verified текущий email постоянных credentials, без pending provisioning/temporary password. Наличие enabled TOTP обязательно; Start не заменяет регистрацию или обычный вход.

Создаются два независимых случайных значения по 256 бит: challenge token и browser binding. SQL хранит scoped keyed digests, не plaintext. В будущем token будет передаваться в POST body, binding — только в Secure/HttpOnly cookie; текущий этап cookie/route ещё не публикует. Один pending challenge на пользователя, TTL задаётся внутренней конфигурацией и ограничен пятью минутами. Новое проверенное primary login заменяет старый challenge, не создаёт сессию и не меняет фактор. В audit не попадают tokens, binding, password hash или OTP.

`Login.Complete` принимает token/binding/код, но не пользовательский UUID, auth_version или MFA timestamp. Владелец берётся из SQL challenge. Порядок блокировок — user → challenge → factor → session; первый digest/binding lookup не блокирует строку. После ожидания user lock отдельный запрос заново проверяет challenge, expiry/attempts/version и исходные credentials. Отзыв/смена credentials или identity, block/delete/version change делают challenge непригодным.

Правильный TOTP/recovery, его потребление, две audit-записи, удаление challenge и INSERT в общую `auth.sessions` коммитятся одной транзакцией. Сбой сессии или audit откатывает всё, включая recovery verifier/TOTP step; raw session token возвращается только после успешного commit. У одного challenge один победитель. Неправильный код коммитит SQL attempts до возврата общей ошибки; максимум пять. Ошибочная browser binding не расходует SQL attempts владельца. Redis completion budget привязан к паре token+binding, поэтому знание одного token не позволяет расходовать бюджет настоящего браузера.

Внутренняя `LoginConfig` требует явных положительных user/IP/project лимитов в минуту и допустимых TTL; скрытых zero-defaults нет. Start и Complete имеют отдельные Redis namespaces/budgets, fail-closed и timeout пять секунд. Completion additionally ограничен пятью обращениями в минуту на пару token+binding; SQL attempts остаются самостоятельной защитой. IP/User-Agent и токены ограничены до зависимостей. Это operational budgets, не capacity/RPS. ENV/сохраняемые настройки подключаются вместе с App/HTTP; дополнительных pools/workers/dependencies нет.

MFA-сессия хранит `primary_method`, `primary_verified_at` и `mfa_verified_at`. PostgreSQL задаёт время второго фактора и сроки сессии; middleware получает context из действующей SQL-сессии, не из клиентского header. Refresh, rotation и password reauthentication не обновляют MFA freshness. У старых/обычных сессий nullable proof отсутствует; они не становятся MFA-authenticated автоматически. Admin enforcement, protected step-up/enroll/replace/disable/regeneration и usable-admin policy ещё не подключены — наличие context само по себе их не заменяет.

Expired challenges очищаются existing bounded retention по expiry index, удаление аккаунта удаляет pending challenge. Reset/version change инвалидируют его логически; сброс пароля не снимает фактор. Ошибка или потеря успешного ответа не позволяют повторно получить использованную сессию: пользователь начинает новый основной вход.

## Подключение фактора

Внутренний `StartEnrollment` получает user UUID, hash текущей сессии и ожидаемую auth_version. Репозиторий проверяет active/nondeleted account, действующую сессию той же версии и password proof не старше пяти минут. Actor/user ID сами по себе не являются доказательством. External-only enrollment с другим свежим primary proof ещё не реализован.

Создаются новый случайный секрет 32 байта, manual key, `otpauth` URI для будущего QR и enrollment token 256 бит. В URI issuer задаёт установка, account label — стабильный UUID, не выдуманный email. Профиль — шесть цифр, 30 секунд, HMAC-SHA1; совместим с обычными TOTP authenticators и не зависит от Google/Gmail login. Используется [pquerna/otp v1.5.0](https://github.com/pquerna/otp/tree/v1.5.0), а не собственная реализация OTP. Параметры и replay policy сверены с [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).

Секрет шифруется существующим AES-GCM Cipher с purpose `mfa:v1`; зашифрованное содержимое включает owner UUID. Перестановка ciphertext между пользователями отклоняется. Новый root key, pool или worker не создаётся. Сборка следующего шага должна передавать scoped cipher из имеющегося operational encryption key; реальные ключи этим шагом не меняются.

Pending enrollment один на пользователя, срок — десять минут, максимум пять неправильных кодов. Повторный start заменяет pending secret/token, но не действующий фактор. Ошибочная попытка подтверждения коммитит счётчик перед возвратом ошибки; infrastructure failure откатывает операцию. Enrollment привязан к той же session hash/auth_version: logout, rotation, block или version change лишают его полномочий. Уже включённый фактор нельзя перезаписать этим сценарием.

`ConfirmEnrollment` заново проверяет свежую сессию и token, валидирует первый код по времени PostgreSQL, затем одной транзакцией сохраняет фактор/использованный time step, десять recovery verifiers, увеличивает auth_version, отзывает все прежние сессии, удаляет pending enrollment и записывает audit. Сбой audit откатывает всё. Ни сессия, ни административные права не выдаются.

Manual key/URI/enrollment token и plaintext recovery codes не сохраняются в аудите и исключены из автоматической JSON-сериализации внутренних результатов. Будущий HTTP DTO должен отдавать их явно только владельцу через защищённый no-store ответ; их нельзя логировать, помещать в URL запросов или включать в telemetry. После потери успешного ответа plaintext коды нельзя перечитать; перевыпуск с новым protected proof — отдельный следующий сценарий.

## Проверка и одноразовость

Внутренний `Verify` — trusted-caller primitive: user UUID/auth_version должны происходить из подтверждённого primary/challenge workflow, не из клиентского JSON. Это проверка и потребление фактора, не самостоятельный login endpoint или переносимый authentication ticket. Возвращённое время нельзя передать обратно как клиентское доказательство.

SQL заново проверяет active/nondeleted пользователя и текущую auth_version, блокирует user перед factor. TOTP допускает только текущий и соседние time steps (±30 секунд). Все кандидаты проверяются, сохраняется наибольший совпавший step; использованный или более старый step повторно не принимается. Браузер не выбирает timestamp. Нужны синхронизированные часы PostgreSQL/устройства; откат часов не сбрасывает защиту replay.

Десять резервных кодов имеют по 128 случайных бит, формат — 32 lowercase hex-символа. SQL хранит только owner-bound keyed SHA-256 verifiers. Успешный recovery удаляет ровно свой verifier и пишет audit в той же транзакции; один код имеет одного победителя даже при параллельных запросах. Отказ аудита сохраняет код для явного повторения. Recovery code не заменяет primary login, не отключает MFA, не меняет password/status/роль и не создаёт сессию.

Redis admission выполняется до SQL: общий бюджет пяти MFA операций в минуту на пользователя и 500 на установку, включая start/confirm/verify. Проверка работает fail-closed при ошибке Redis. Это текущие внутренние бюджеты, не измеренная пропускная способность проекта; operational ENV/настройки будут подключены вместе с публичным flow. Для public challenge дополнительно нужны IP/send/attempt bounds A5.2. Unit/SQL тесты используют разрешающий limiter для проверки SQL-конкуренции; live Redis этого нового namespace ещё не проверен.

## Сессии и lifecycle

Общий PostgreSQL `CreateSession` после user lock/current version check выполняет один дополнительный PK-based EXISTS для active TOTP. Если фактор есть, возвращает `session/domain.ErrMFARequired` без INSERT. Все существующие primary methods используют эту выдачу, поэтому сменой password на OIDC/email OTP обойти фактор нельзя. Отдельный запрос после ожидания блокировки и explicit Read Committed исключают устаревший снимок enrollment. Фактор не кешируется; роль Redis в остальных сценариях не меняется. Session cache этим шагом не добавляется.

После отдельного `Verify` этот запрет тоже остаётся: открывать его boolean-полем или клиентским timestamp нельзя. A5.2a-local связывает primary proof, browser challenge, factor consumption и session context атомарно через `Login.Complete`; самостоятельный Verify не выдаёт login authority. `consumeFactor` переиспользуется без копирования OTP/recovery логики.

Password reset/change и защитное account recovery не удаляют фактор. Удаление аккаунта очищает pending/enabled secrets и recovery verifiers; audit сохраняется по общей политике. Existing retention worker удаляет expired enrollment индексируемыми bounded batches и MFA audit через SECURITY_AUDIT_RETENTION_DAYS, по умолчанию 180 дней. У модуля нет собственного polling loop или goroutine.

## Открытые части A5

- Подключение реализованного login challenge к password/OIDC/email OTP и HTTP; effective enabled/verification policy, безопасная cookie/Origin семантика и публичные ошибки.
- Свежая проверка второго фактора и enforcement для admin operations; client-provided MFA flags запрещены. Session context реализован, protected step-up ещё нет.
- Protected отключение/замена TOTP и перевыпуск recovery codes, current role/policy/last-admin guards; обычный reset не становится lost-factor bypass.
- External-only fresh proof/enrollment, required MFA по ролям, безопасный first-admin setup и отдельный lost-factor процесс.
- App/router/Swagger, operational ENV, browser/live authenticator/Redis/fault/mixed-load acceptance; настройки A6 и UI A7.
- SMS после выбора provider; passkeys вне текущего выпуска.

Расширена только исходная `000001_init`: mfa_totp, mfa_enrollments, mfa_login_challenges, mfa_recovery_codes, mfa_audit и nullable session authentication context. Уже применённой установке нужен отдельно согласованный upgrade, не reset или повторный migrate up. Рабочая БД/secrets/env не изменялись.
