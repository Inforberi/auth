# Сохраняемые настройки Auth — A6

## Текущий статус

A6.1-local реализует domain/service/PostgreSQL store и first-install seed. A6.2a-local добавляет независимый административный password+MFA login. A6.2b-local подключает startup и runtime enforcement сохраняемой публичной политики. **Settings API и UI ещё не опубликованы**: менять профиль через HTTP можно будет после A6.2c. ENV-флаги методов используются только при первой инициализации, credentials/operational параметры пока остаются в ENV.

Далее A6.2c — protected read/update API с проверкой готовности включаемых adapters. A6.3 — MFA policy по ролям, SMTP/provider secrets и retention settings. Их поля и пустые adapters сейчас не создаются.

## Публичная политика в работе — A6.2b-local

App сначала загружает/инициализирует policy через существующий store, затем собирает adapters. Сохранённая строка не перезаписывается ENV-флагами после перезапуска. Ошибка SQL или потеря settings после initialized setup marker не разрешают fallback на ENV/defaults. Config.New проверяет deployment-параметры до SQL; optional provider credentials проверяются по сохранённому профилю после загрузки policy.

Парольный login/registration, provider start/callback/link и запрос/подтверждение email OTP получают ранний live policy read. Он выполняется после существующих admission limits и до hashing/provider exchange/SQL consume; регистрация уже ограничена HTTP registration budgets. Это проверка допуска, не гарантия финального commit. Прямые SQL use cases независимо проверяют политику при регистрации аккаунта/identity, linking, выдаче/потреблении OTP и обычной/MFA SQL-сессии. Password verification required также проверяется перед стартом/завершением public MFA и public lost-factor recovery. Административный intent остаётся независимым.

На финальных транзакциях используется singleton `FOR SHARE` **после account/identity locks**. Public readers совместимы между собой; settings Update использует прежний `FOR UPDATE` и ждёт их commit. Если изменение политики закоммичено первым, следующий final read видит новые flags; если вход первым удержал shared lock, он завершается перед изменением. Нет интервала кеша, pub/sub или polling: все экземпляры читают один SQL authority. Пулы и operation deadlines остаются прежними. После policy lock нельзя брать новый user lock: порядок согласован с Access → actor/user → settings в Update.

Password registration:

- `optional`: атомарно создаёт аккаунт и queued verification, затем обычную session, как раньше.
- `disabled`: не готовит/не ставит автоматическое registration-письмо и не помечает email verified; обычный вход разрешён. Ручное доказательство владения почтой и sensitive/recovery/binding guards независимы от этого флага.
- `required`: создаёт аккаунт и queued verification, возвращает `201 {"userID":"…","verificationRequired":true}` без новой session cookie. До реального подтверждения password login возвращает `403 email_not_verified`; подтверждение само не входит, затем нужен новый login. Регистрация и session — разные commits: переключение policy между ними не выдаёт запрещённую session, а при необходимости письмо можно запросить через resend. Повторная регистрация существующего адреса не входит автоматически.

Отключённый метод возвращает `404 method_disabled`, закрытая публичная регистрация — `403 registration_disabled`; SQL policy unavailable — `503 temporarily_unavailable` без деталей зависимости. Отказ перед consume не тратит OTP/recovery code. Уже потреблённый provider state/OTP не восстанавливается при ошибке последующей session-транзакции: как и раньше, flow начинают заново. Пока метод отключён, pending callback/MFA не обходят флаг; при повторном включении ещё живой непотреблённый challenge может быть завершён до своего прежнего TTL.

Выключение метода или включение required verification **не являются logout-all для уже выданных сессий**. Новые входы существующих пользователей следуют новой политике, а действующие sessions сохраняют прежние expiry/status/auth_version/revoke и sensitive email/MFA guards. Session validation/refresh/rotation не добавляют policy read на каждый запрос. Для немедленного прекращения доступа используются существующие logout-all/block/revoke механизмы. Новые plain login sessions сохраняют primary method/time; provider/email OTP не превращаются в password intent.

Configured Google/Telegram adapters собираются независимо от текущего публичного switch и проверяют live policy: их можно выключать/включать без перезапуска, не удаляя identities. Не настроенный и выключенный provider не требует secrets и не получает handler; включённый сохранённый provider с неполной конфигурацией останавливает startup. Для включения отсутствовавших credentials по-прежнему нужны ENV + restart до A6.3; settings API A6.2c обязан проверять runtime readiness и согласованность конфигурации экземпляров. Email OTP с валидными operational параметрами тоже готов к включению; используются существующие bounded outbox runner/SMTP, не отдельный polling политики. ENV задаёт его бюджеты, не новое значение сохранённого switch.

Settings read/update HTTP routes пока отсутствуют. Локально проверены modes, прямые SQL/HTTP отказы, текущая authority, provider registration preference, plain primary context, pending MFA/OTP и shared/exclusive commit ordering. Настоящие provider credentials, SMTP/browser/operator drill и load/GC этим этапом не проверялись.

## Административный вход — A6.2a-local

`POST /api/v1/admin/auth/login/email` принимает тот же JSON `{ "email": "admin@example.com", "password": "…" }`, что публичный password login. Нужен разрешённый HTTPS Origin; ручка доступна при `MFA_ENABLED=true` и подключённом MFA handler. Это вход существующего администратора, не регистрация и не выдача роли.

Условия: active/nondeleted пользователь, актуальный постоянный пароль, подтверждённый email именно password credentials, завершённая активация без обязательной смены/временного пароля и enrolled TOTP. Нужна текущая system membership `super_admin` либо хотя бы одно из восьми встроенных административных permissions каталога Access, включая делегированную custom роль. Продуктового permission вроде `reports.read` недостаточно. Успешный вход не расширяет доступ: каждая административная ручка по-прежнему проверяет своё конкретное permission и необходимые fresh proofs.

Ответ всегда `202 mfa_required` с challenge и browser-binding cookie, без новой session cookie. Используются прежние проверка/rehash пароля, Redis password limits и общий MFA guessing budget. Неподходящий административный профиль возвращает нейтральное `400 invalid_credentials`, без раскрытия роли, отсутствующего фактора или verified contact. Формат запроса и ошибки зависимостей сохраняют обычный password контракт. При отключённом MFA новая ручка отсутствует (`404`); внутренний SessionService тоже запрещает password-only fallback для административного intent.

Завершение — существующий `POST /api/v1/auth/mfa/login/complete`, challenge + TOTP или одноразовый recovery code, с browser cookie и Origin. До потребления фактора SQL снова проверяет текущие credentials, readiness и административную authority. Отзыв роли/permission, блокировка, смена пароля/version или утрата verified email не разрешают завершить старый административный вход. Отказ не расходует recovery code. Session insert, одноразовый consume, удаление challenge и audit атомарны.

Выдаётся обычная SQL-сессия, без отдельного admin token, session store или расширения срока. В ней `password_verified_at` равен времени исходного password proof, а не моменту MFA: ожидание второго фактора не продлевает свежесть пароля. `mfa_verified_at` задаётся существующей SQL-проверкой фактора. Публичные MFA-сессии не получают этот административный password context автоматически.

Intent выбирает доверенный password service, не JSON. Он сохраняется в `auth.mfa_login_challenges.administrative`; constraint допускает его только для password. Один пользователь имеет один текущий login challenge: новый публичный или административный вход заменяет предыдущий и не наследует его intent/операторское одобрение. На final commit повторно проверяется именно сохранённый intent. Публичный `AllowPrimary` не выключает частный admin intent; его собственные password/readiness/authority/MFA проверки обязательны.

Opt-in lost-factor recovery использует тот же сохранённый intent и заново проверяет authority на request/complete. Операторское одобрение не сохраняет отозванные права. Успешная замена фактора по-прежнему не выдаёт сессию: затем выполняется новый вход. Этот путь не включает recovery и не отменяет обязательную внешнюю приёмку 13.1d.4.

Administrative challenge start/complete берут существующий Access advisory lock перед user/challenge/factor locks, согласуясь с редактированием ролей. Публичный login не получает глобальной блокировки. Проверка readiness — bounded indexed lookup; нет сканирования всех пользователей, нового polling/cache/pool/worker. Источник 000001 дополнен колонкой для новой установки; рабочие БД не мигрировались. Локальные тесты не заменяют pre-ui-backend и не устанавливают RPS.

## Что хранится

| Группа | Поля и назначение |
| --- | --- |
| PublicMethods | Независимые Password, EmailOTP, Google, Telegram |
| PublicRegistration | Общий Enabled, отдельные разрешения регистрации Google/Telegram |
| PasswordEmailVerification | disabled / optional / required |
| Snapshot.Version | Версия всего не-секретного профиля для optimistic updates |

Registration.Enabled — общий запрет создания аккаунтов через публичные методы. Provider registration требует также включённого метода и собственного разрешения регистрации. Password registration подчиняется общему флагу. Email OTP пока входит только в существующий аккаунт и не получает автоматическую регистрацию. Выключение метода или регистрации не удаляет identities/аккаунты и не стирает предпочтения других флагов.

Verification задаётся одним enum вместо двух bool: состояние «required, но verification отключена» невозможно выразить. Disabled не отправляет автоматическое registration письмо и не подделывает verified_at; optional сохраняет доступ без обязательного подтверждения; required не выдаёт новую полноценную password session до email proof. Proof владения почтой в recovery/change/binding и административном setup независим от публичной registration policy. Правила переключения для существующих пользователей/сессий описаны выше; UI не заменяет SQL enforcement.

Все публичные методы можно выключить, оставив закрытую админку, либо выключить публичный password для OAuth-only сайта. Административный password+TOTP профиль не представлен изменяемыми флагами. Admin intent реализован в A6.2a-local, enforcement публичных переключателей — в A6.2b-local выше. Settings API остаётся A6.2c.

## Источник и инициализация

`Config.InitialAuthPolicy()` формирует seed только из не-секретных полей текущего ENV-профиля: password/public registration включены, verification optional, enabled/registration preferences Google/Telegram и enabled Email OTP взяты из их конфигурации. SMTP/provider secrets и root key в Policy не попадают.

`Service.Initialize` предназначен только для доверенного startup-кода, не HTTP. Сначала загружается сохранённая строка. Если она есть, переданный seed игнорируется, включая невалидный seed: ENV не перезаписывает решения оператора. При реальном отсутствии строки seed проверяется и создаётся под тем же Access advisory lock, что initial setup. Конкурентные initializers получают один winner/snapshot с version=1; проигравший не перезаписывает его. Ошибка SQL не считается первой установкой и не вызывает fallback на defaults.

Если durable initial_setup marker уже initialized, а settings row потеряна, Initialize отказывает. Это повреждение/несогласованный upgrade, а не повод молча сбросить настройки в ENV. Первоначальная запись не получает выдуманного actor или change audit; последующие изменения требуют подтверждённого оператора. Конфигурационная строка не очищается retention.

Ранее изменены исходные 000001 up/down для новой установки, без нового migration file и без сброса рабочей БД; A6.2b схему не меняет. Уже установленному экземпляру нужны отдельно согласованные schema/seed/permission upgrade. Нельзя запустить новую retention/startup логику на старой схеме без settings/audit tables или молча восстановить потерянную policy после setup из ENV.

## Права и транзакция

Нужно отдельное `auth.settings.manage`. Оно выдаётся первому супер-администратору новой установки и может быть явно делегировано custom ролью через прежние delegation guards. Знание UUID, management permissions других фич или сама membership без этого permission не дают настройки. Существующие роли автоматически не расширяются.

Read проверяет live SQL session/status/auth_version и permission в одном SQL statement; нового password/MFA proof для чтения не требуется. Это read не-секретных flags, не credentials. Load — отдельный внутренний configuration read без actor; его нельзя публиковать как administrator API.

Update принимает actor из trusted session context, ExpectedVersion и целый типизированный Policy. Service один раз проверяет форму principal, положительную версию и domain enum. Репозиторий в Read Committed транзакции берёт Access lock, текущие actor/session locks и проверяет current permission, fresh password/MFA и enrolled factor через существующий AuthorizeMutation. Затем блокирует единственную settings row и сверяет версию. После ожидания Access lock старая permission/membership не разрешает запись, даже если connection default isolation — repeatable read.

Реальное изменение повышает version на один и пишет предыдущий/новый не-секретный Policy вместе с actor/version/time в auth_settings_audit. Ошибка аудита откатывает и профиль, и version. No-op с текущей version не создаёт audit/version bump, но снова проверяет authority/proofs. Старая version всегда conflict; автоматических retries нет. Deadline сервиса 3s, cleanup rollback ограничен 5s.

Права `auth.settings.manage` недостаточно для назначения super_admin или изменения фиксированной административной защиты. Обладатель этого чувствительного permission не может отключать свой MFA; SQL MFA policy расширена вместе с permission. Новая установка получает восемь core permissions, каталог по-прежнему ограничен 512: до 504 продуктовых + восемь встроенных.

## Производительность и аудит

Одна singleton строка, primary key lookup, редкие исключительные изменения и совместные final reads. Добавлены bounded early admission/final transaction reads, но не запросы на каждый session middleware. Settings не создаёт новых pools/workers/cache/policy polling и не делает UPDATE всех пользователей; подготовленные методы используют прежние delivery runners и бюджеты. На MFA-enabled входе первый session probe не читает политику повторно, а передаёт её проверку владельцу challenge-транзакции. Независимый административный вход использует собственные authority checks.

Audit хранит только типизированные flags/enum, а не общий Config, тела HTTP, SMTP passwords или provider secrets. Снимки ограничены 4096 байт SQL constraints. Старые audit rows очищаются существующим bounded/indexed retention worker по SECURITY_AUDIT_RETENTION_DAYS; профиль и его версия остаются. Параметры retention пока остаются в ENV.

Локально проверены initialization races/no ENV overwrite, отказ после initialized marker при потере строки, delegated/revoked authority, fresh proof, version/no-op, concurrent updates, audit rollback, отказ после lock wait/revoke, SQL constraints и audit retention. Это не реальная SMTP/provider/browser приёмка и не замер HTTP RPS. Перед UI обязателен pre-ui-backend, затем A8 и открытый operator recovery drill.
