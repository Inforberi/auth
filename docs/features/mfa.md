# MFA: TOTP и резервные коды

## Текущее состояние

A5.1-local — проверенная внутренняя основа, не готовый публичный вход с MFA. Реализованы enrollment, подтверждение первого TOTP, одноразовое потребление TOTP/recovery, SQL-хранение и ограничения. Модуль пока не собран в App и не подключён к router: в Swagger нельзя включить MFA пользователю. Полный A5 не закрыт.

Следующий A5.2 подключит общий ограниченный challenge после password/OIDC/email OTP, проверку второго фактора и атомарную выдачу обычной сессии. До него нельзя вручную включать фактор в рабочей БД: обычная выдача сессии такому аккаунту намеренно закрыта, а публичного completion ещё нет.

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

После потребления фактора этот запрет тоже остаётся: открывать его boolean-полем или клиентским timestamp нельзя. A5.2 должен связать current primary proof, browser challenge, factor consumption и session authentication context атомарно. `consumeFactor` уже отделён внутри PostgreSQL adapter для использования в такой транзакции, без копирования OTP/recovery логики.

Password reset/change и защитное account recovery не удаляют фактор. Удаление аккаунта очищает pending/enabled secrets и recovery verifiers; audit сохраняется по общей политике. Existing retention worker удаляет expired enrollment индексируемыми bounded batches и MFA audit через SECURITY_AUDIT_RETENTION_DAYS, по умолчанию 180 дней. У модуля нет собственного polling loop или goroutine.

## Открытые части A5

- Browser-bound login challenge после всех primary methods, ограниченные ошибки/попытки/TTL и атомарная выдача общей SQL-сессии.
- Session MFA authentication context и свежая проверка второго фактора для admin operations; client-provided MFA flags запрещены.
- Protected отключение/замена TOTP и перевыпуск recovery codes, current role/policy/last-admin guards; обычный reset не становится lost-factor bypass.
- External-only fresh proof/enrollment, required MFA по ролям, безопасный first-admin setup и отдельный lost-factor процесс.
- App/router/Swagger, operational ENV, browser/live authenticator/Redis/fault/mixed-load acceptance; настройки A6 и UI A7.
- SMS после выбора provider; passkeys вне текущего выпуска.

Расширена только исходная `000001_init`: mfa_totp, mfa_enrollments, mfa_recovery_codes, mfa_audit. Уже применённой установке нужен отдельно согласованный upgrade, не reset или повторный migrate up. Рабочая БД/secrets/env не изменялись.
