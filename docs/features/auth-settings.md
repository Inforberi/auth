# Сохраняемые настройки Auth — A6

## Текущий статус

A6.1-local реализует внутренние domain/service/PostgreSQL store и first-install преобразование конфигурации. A6.2a-local добавляет независимый административный password+MFA login. **Settings API, UI и runtime enforcement сохраняемой публичной политики ещё не подключены.** Приложение по-прежнему использует ENV; сохранённые флаги пока нельзя считать действующими настройками входа. Settings routes и Swagger для незавершённого сценария намеренно не публикуются.

Далее A6.2b: подключить политику ко всем login/callback/registration/session/MFA consumers; A6.2c — только после этого опубликовать read/update API. A6.3 — MFA policy по ролям, SMTP/provider secrets и retention settings. Их поля и пустые adapters сейчас не создаются.

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

Verification задаётся одним enum вместо двух bool: состояние «required, но verification отключена» невозможно выразить. В A6.2 disabled не отправляет автоматическое registration письмо и не подделывает verified_at; optional сохраняет доступ без обязательного подтверждения; required не выдаёт обычную полноценную session до email proof. Proof владения почтой в recovery/change/binding и административном setup независим от публичной registration policy. Смена policy для существующих пользователей/сессий требует отдельного enforcement A6.2, а не только новой UI подписи.

Все публичные методы можно выключить: это будущий профиль закрытой админки. Публичный password можно выключить для OAuth-only сайта. Поэтому административный password+TOTP профиль не представлен изменяемыми флагами в этой модели. Отдельный admin login intent реализован в A6.2a-local выше. Применение переключателей публичного входа и settings API остаются A6.2b/c; без полного enforcement API не открывается.

## Источник и инициализация

`Config.InitialAuthPolicy()` формирует seed только из не-секретных полей текущего ENV-профиля: password/public registration включены, verification optional, enabled/registration preferences Google/Telegram и enabled Email OTP взяты из их конфигурации. SMTP/provider secrets и root key в Policy не попадают.

`Service.Initialize` предназначен только для доверенного startup-кода, не HTTP. Сначала загружается сохранённая строка. Если она есть, переданный seed игнорируется, включая невалидный seed: ENV не перезаписывает решения оператора. При реальном отсутствии строки seed проверяется и создаётся под тем же Access advisory lock, что initial setup. Конкурентные initializers получают один winner/snapshot с version=1; проигравший не перезаписывает его. Ошибка SQL не считается первой установкой и не вызывает fallback на defaults.

Если durable initial_setup marker уже initialized, а settings row потеряна, Initialize отказывает. Это повреждение/несогласованный upgrade, а не повод молча сбросить настройки в ENV. Первоначальная запись не получает выдуманного actor или change audit; последующие изменения требуют подтверждённого оператора. Конфигурационная строка не очищается retention.

Изменены исходные 000001 up/down для новой установки, без нового migration file и без сброса рабочей БД. Уже установленному экземпляру нужны отдельно согласованные schema/seed/permission upgrade. Нельзя просто запустить новую retention-логику на старой схеме без новой audit table. При подключении startup в A6.2 этот порядок остаётся обязательным.

## Права и транзакция

Нужно отдельное `auth.settings.manage`. Оно выдаётся первому супер-администратору новой установки и может быть явно делегировано custom ролью через прежние delegation guards. Знание UUID, management permissions других фич или сама membership без этого permission не дают настройки. Существующие роли автоматически не расширяются.

Read проверяет live SQL session/status/auth_version и permission в одном SQL statement; нового password/MFA proof для чтения не требуется. Это read не-секретных flags, не credentials. Load — отдельный внутренний configuration read без actor; его нельзя публиковать как administrator API.

Update принимает actor из trusted session context, ExpectedVersion и целый типизированный Policy. Service один раз проверяет форму principal, положительную версию и domain enum. Репозиторий в Read Committed транзакции берёт Access lock, текущие actor/session locks и проверяет current permission, fresh password/MFA и enrolled factor через существующий AuthorizeMutation. Затем блокирует единственную settings row и сверяет версию. После ожидания Access lock старая permission/membership не разрешает запись, даже если connection default isolation — repeatable read.

Реальное изменение повышает version на один и пишет предыдущий/новый не-секретный Policy вместе с actor/version/time в auth_settings_audit. Ошибка аудита откатывает и профиль, и version. No-op с текущей version не создаёт audit/version bump, но снова проверяет authority/proofs. Старая version всегда conflict; автоматических retries нет. Deadline сервиса 3s, cleanup rollback ограничен 5s.

Права `auth.settings.manage` недостаточно для назначения super_admin или изменения фиксированной административной защиты. Обладатель этого чувствительного permission не может отключать свой MFA; SQL MFA policy расширена вместе с permission. Новая установка получает восемь core permissions, каталог по-прежнему ограничен 512: до 504 продуктовых + восемь встроенных.

## Производительность и аудит

Одна singleton строка, primary key lookup, редкие сериализованные изменения; сам settings store не добавляет pools, workers, polling loops, Redis roundtrips или запросов в публичный login/middleware path. Редактирование не делает UPDATE всех пользователей. Runtime propagation и policy/session commit согласованность — обязательная работа A6.2b, не обещание уже существующего кеша или hot reload. Независимый административный вход использует описанные выше authority checks.

Audit хранит только типизированные flags/enum, а не общий Config, тела HTTP, SMTP passwords или provider secrets. Снимки ограничены 4096 байт SQL constraints. Старые audit rows очищаются существующим bounded/indexed retention worker по SECURITY_AUDIT_RETENTION_DAYS; профиль и его версия остаются. Параметры retention пока остаются в ENV.

Локально проверены initialization races/no ENV overwrite, отказ после initialized marker при потере строки, delegated/revoked authority, fresh proof, version/no-op, concurrent updates, audit rollback, отказ после lock wait/revoke, SQL constraints и audit retention. Это не реальная SMTP/provider/browser приёмка и не замер HTTP RPS. Перед UI обязателен pre-ui-backend, затем A8 и открытый operator recovery drill.
