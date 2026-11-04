# Project deployment capabilities для способов входа

MP5.1d, 25 октября 2026. Реализовано, локальные проверки Luna PASS.

Один необязательный PLATFORM_PROJECT_AUTH_CONFIG_FILE задаёт versioned deployment-owned JSON: список записей по неизменяемому UUID проекта, browser/OTP/reauth/Google/Telegram capabilities и optional JWT resources/catalog/hashed consumers/native profile. Не выбирать manifest по Host/path/body или JWT. Отсутствие UUID в явно заданном файле — закрытый профиль, не глобальный fallback. Пустой ENV сохраняет прежний ограниченный password/email source.

Файл читается один раз при startup, ограничен1MiB; JSON unknown/duplicate/case-duplicate fields/trailing values отвергаются. Существующий strict JSON checker access catalog переиспользуется через небольшой infra decoder, без копии правил. Существующие Catalog/NewProjectTokens/Factory/Introspection validators проверяют предметные настройки; импорт permissions в SQL автоматически не выполняется.

Issuer/callbacks строятся только из проверенного project origin. Signing key/encryption key, SMTP и provider credentials берутся прежними project factories, не из глобальных файлов или ENV. Manifest допускает только hashes service secrets, не raw secret/private key/URL issuer. Общие durations/limiter budgets — operational defaults, не авторизация. Выдача пересекается с current SQL policy.

Shared OIDC clients и отдельный no-retry token Redis создаются один раз на процесс, только при реально выбранных deployment capabilities. Drain HTTP предшествует их закрытию, registry/reader закрываются прежними owners. CORS/server/phase-ready/UI и полная MP5 матрица не открываются автоматически. Основная работа — подключение готовых методов, не новый Auth flow/SSO.

Main formatter/source review, Luna task check/API-if-changed/affected race/security и actual command/runtime/operator SQL acceptance на синтетических данных. Внешний Google/Telegram/SMTP login без secrets не считать проверенным.

`LoadProjectAuthDeployment` возвращает immutable source с `Profile(ctx,key,origin)`; его можно использовать в существующих app/command fixtures без второго parser или копии настройки. Поля source закрыты. Deployment changes требуют restart, SQL policy по-прежнему проверяется на запросах.

## Настройка

Для управления email добавлены `emailBinding` и `emailChange` (default false, только browser). Binding дополнительно требует `reauthentication=true` и MFA config; actor права проверяются отдельно в проектной SQL. Producer зависит от SMTP/delivery, completion/protection — от SQL/Redis и выданных proofs. URLs строятся из origin проекта; подробности и шесть маршрутов — в [контракте email management](project-email-management.md).

Включить существующий `PLATFORM_PROJECT_HTTP_ENABLED` и указать `PLATFORM_PROJECT_AUTH_CONFIG_FILE` с deployment-owned файлом. [Пример](../../deploy/examples/project-auth.example.json) содержит синтетический UUID: заменить на реально подготовленный проект. Реальные ENV/секреты этим блоком не менялись. Файл загружается при startup, hot reload отсутствует; изменение требует restart.

| Поле записи | Значение |
| --- | --- |
| id | Exact canonical project UUID в текущем realm |
| browser | Доступность browser password/регистрации/MFA/verification/recovery; фактическое включение — SQL policy |
| emailOTP | OTP capability для browser и/или native в зависимости от профиля |
| emailMFA | Второй фактор после пароля, default false; требует browser, MFA engine, project delivery/SMTP и отдельное recovery readiness |
| reauthentication | Email proof для действующей browser session; требует browser=true |
| google / telegram | Browser OIDC capability; требуется browser=true и сохранённые project credentials |
| jwt | Optional project resources/catalog/consumers, без ключей подписи или произвольного issuer |
| jwt.native | Наличие native refresh/MFA profile; SQL native policy проверяется отдельно |
| jwt.password | Native password capability; требует jwt.native=true |
| jwt.permissions | Каталог разрешений JWT resources, проверяется existing access catalog rules; не создаёт permission grants/roles в SQL |
| jwt.resources | Existing audiences/modes/permissions, включая различие strict/local revoke |
| jwt.clients | Необязательные service client id/secretHashes/audiences для introspection |

`secretHashes` — прежний формат SHA-256 в canonical lowercase hex, по1..2 на client; это не plaintext secret. Raw secrets/signing key/issuer/callback полями файла не принимаются. Один consumer hash между разными project UUID запрещён, чтобы копирование manifest не создало общие service credentials. Authority в запросе всё равно проверяется existing project introspection service.

Для mail capabilities нужен включённый project delivery и сохранённый SMTP; отсутствие секрета не заменяется глобальным. Native password с verification policy использует общий verification flow, а не автоматическое подтверждение email при JWT-входе. Сессионный exchange работает только с текущей SQL browser session; JWT-only профиль получает явный operational session validation config при сборке.

## Гарантии и ресурсы

Resources/client hashes/native durations проверяются при загрузке через существующие domain predicates, которые используют реальные конструкторы. Неизвестный permission/audience/client hash закрывает startup manifest безопасной ошибкой без raw JSON. При сборке конкретного проекта конструкторы повторно проверяют свои контракты, current SQL key/policy и сохранённые credentials. Раннее чтение deployment config не заменяет SQL authority.

Source хранит только очищенные operational values и приватные immutable записи, каждый `Profile` возвращает независимые изменяемые slices и provider config. Проверяется принадлежность runtime key текущему realm. Заданный файл с пустым projects разрешён как явно закрытый deployment; неизвестный UUID не получает парольный или JWT fallback. Без файла сохраняется прежний password/email source и новые owners не создаются.

При выбранном Google/Telegram создаётся одна process-owned пара existing clients/transports/key caches. При любом JWT — один shared no-retry token Redis pool с пределом8 connections (дополнительно к основному Redis pool), MinIdle0, без pool на каждый проект. SQL pools не добавляются. LIFO порядок: HTTP dispatcher drain → token Redis/OIDC clients → registry/private reader → основные зависимости. Ошибка сборки закрывает уже созданные owned resources.

## Проверки

Unit: strict JSON ambiguity/UTF8/unknown/trailing; duplicate UUID/realm mismatch; callback/issuer derivation; deep-copy snapshots; closed/missing profile; malformed JWT/resources/hashes и cross-project shared consumer hash. Общий JSON decoder используется и старым access catalog, его regression обязателен.

Actual runtime assembly fixture запрашивает OIDC/JWT owners на пустом каталоге, TLS unknown Host остаётся404 до Redis/profile build; операторский маршрут не становится fallback. Actual command HTTPS fixture использует настоящий manifest source для browser/native/JWT/introspection, проверяет native SQL toggle/stale rebuild/JSON transport, service401 без credentials и403 с browser Origin. Это не успешный внешний OAuth/SMTP или полноценная two-project acceptance.

Main formatter/diff/read-only review. Luna task check, affected race/security, actual command/runtime/operator SQL suites PASS (Linux ARM64, без SKIP). Новых зависимостей/schema/UI/SSO нет; полный MP5/MP7/MP8 и phase-ready publication не закрыты этим блоком.


Итог Luna: task check, targeted race, security и все три actual SQL regressions PASS. TLS verification, неверный SCRAM password deny и RedisDB15 preflight подтверждены. Manifest13 совпал после прогона и с main, перенесённый старый checker не восстановлен; ENV/JSON examples совпали. Собственные containers/network/fixture/binaries удалены. Внешний OAuth/SMTP и полная two-project/MP5/MP7/MP8 приёмка этим результатом не закрыты.

Для проектного списка и карточки пользователей предусмотрен `userDirectory` (default false, требует `browser=true`). Это только публикация двух GET endpoints: право `accounts.users.read` и текущая проектная SQL-сессия обязательны отдельно. [Контракт](user-directory.md#независимые-проекты--mp51k).

Для административного создания пользователей добавлены независимые `invitations` и `temporaryPassword` (default false, требуют browser). Существующие operational budgets копируются отдельно для проекта, invitation URL — его origin + `/activate`; MFA/SQL-права проверяются отдельно. [Контракт](project-user-provisioning.md).

`userLifecycle` (default false, browser only) подключает проектные status/delete endpoints с отдельными SQL permissions и свежими password/MFA proofs. [Контракт и ограничения](project-user-lifecycle.md).

Опциональный `access: {"permissions": [...]}` включает проектные API ролей/разрешений (browser only); отсутствие объекта default-off, пустой объект — built-in catalog. Чтение отдельно от MFA-dependent mutations; дополнительные permissions выбираются по UUID и не наследуются из platform catalog. [Контракт](project-access-management.md).

`authSettings` (default false, требует browser) подключает local Auth policy GET/POST; actual readiness, version/permission/fresh-proof и SQL dependency pins описаны в [контракте настроек](project-auth-policy-settings.md). SMTP/provider/retention endpoints этим флагом не включаются.

`smtpSettings` (default false, browser only) публикует project SMTP GET/POST/test. Existing project delivery allowlist остаётся deployment-only, секреты scoped по проекту, probe не удерживает SQL lease. [Контракт](project-smtp-settings.md).

`providerSettings` (default false, browser only) подключает local Google/Telegram credentials GET/POST независимо от enabled login methods. Scoped crypto/SQL revision guards и ограничения смены clientId — в [контракте](project-provider-settings.md).

`retentionSettings` (по умолчанию false, требует browser) подключает проектные GET/POST сроков хранения. Подтверждение сокращения, версии и применение worker — в [контракте](project-retention-settings.md).

## Email MFA из manifest — A6.3m.6c.4b.3

Принято после Luna V2: task check/config-app-router race и actual manifest-backed HTTP/SQL/Redis PASS/exit0, cleanup подтверждён; evidence — [history](../planning/history.md). `emailMFA: true` выбирается явно для UUID проекта; поле отсутствует/false — capability не собирается. Без manifest прежний ограниченный профиль сохраняется. ENV сами по себе метод не включают. [Пример manifest](../../deploy/examples/project-auth.example.json) оставляет `emailMFA: false`.

Это capability, а не `auth.mfa_settings.email_factor_allowed`: сохранённая политика проекта отдельно разрешает фактор, пользователь отдельно подтверждает принадлежащий ему verified email и подключает его. Политикой/личной настройкой нельзя заменить отсутствующий runtime. Для настройки политики через проектный API отдельно включается `mfaSettings`; права и fresh proofs остаются обязательными.

Статический loader отклоняет selected emailMFA без browser, `MFA_ENABLED`, включённого project delivery с непустым SMTP allowlist, корректной общей MFA config и положительных/допустимых channel/change budgets. Реальная готовность Redis, SMTP credentials, running delivery и отдельной NOLOGIN DB recovery group проверяется при сборке ProjectProfile. Конфигурационная readiness не гарантирует работоспособность внешнего SMTP.

Email-only аккаунту необходим безопасный путь потери почты: selected capability собирает existing browser operator-assisted recovery. RecoveryEnabled=true устанавливается только на копиях project Password/EmailOTP/Google/Telegram/native MFA config, чтобы browser policies были согласованы. Глобальный `MFA_RECOVERY_ENABLED`, конфигурация оператора платформы и другие проекты не меняются; runtime не получает права approval. Сохраняются project DB grants, самостоятельная проверка личности и existing CLI decision workflow. Не создавать operator group/grants автоматически через manifest.

| ENV | По умолчанию | Что ограничивает |
| --- | --- | --- |
| PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_TTL | 3m | Срок proof подготовки канала; допустимо 1–5m |
| PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_RESEND_INTERVAL | 1m | Пауза отправки; минимум 1s, строго меньше TTL |
| PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE | 100 | Запросы подготовки за минуту на каждый проект |
| PLATFORM_PROJECT_EMAIL_MFA_PREPARATION_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE | 1000 | Подтверждения подготовки за минуту на каждый проект |
| PLATFORM_PROJECT_EMAIL_MFA_USER_CHANGES_PER_MINUTE | 5 | Enable/Disable за минуту на пользователя |
| PLATFORM_PROJECT_EMAIL_MFA_PROJECT_CHANGES_PER_MINUTE | 500 | Enable/Disable суммарно за минуту на проект |

Login использует прежние MFA_USER/IP/PROJECT_OPERATIONS_PER_MINUTE и MFA_LOGIN_CHALLENGE_TTL; resend/guessing SQL/Redis guards не ослаблены. Это operational defaults для независимо scoped проектов, не общий счётчик всех проектов, не RPS и не постоянный максимум пользователей. Явный ноль не превращается в default: выбранная capability будет отклонена; синтаксически неверные ENV отвергает config parser. Изменение manifest/ENV требует restart, hot reload отсутствует.

Если ранее email policy/bindings сохранены, а deployment capability удалена или её зависимости не готовы, cold profile отказывает по existing CheckEmailCapability. Перед удалением opt-in следует штатно отключить личные bindings/проектное разрешение; автоматического downgrade или массового удаления нет. Административный email-only вход по-прежнему закрыт: нужны TOTP для совместимого административного профиля, strong proof для критических действий.

Приёмка включает env parsing/defaults/explicit-zero, static prerequisites, копии конфигурации и realm/UUID isolation, existing standalone/operator route contract и actual TestTwoProjectEmailMFAHTTP. Этот тест теперь использует настоящий временный manifest → LoadProjectAuthDeployment → ProjectHTTP, без вручную возвращённого профиля. Внешние SMTP secrets/доставка, production capacity и UI этим блоком не заявляются. Реальные ENV/manifest/БД этим изменением не редактировались.
