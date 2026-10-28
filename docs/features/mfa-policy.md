# Политика обязательности MFA

## Целевое поведение

Владелец платформы выбирает обязательность MFA отдельно от проектов. В каждом проекте можно потребовать второй фактор для всех, для выбранных ролей либо оставить добровольное подключение. Уже подключённый личный фактор продолжает требоваться при входе после снятия обязательности. Требования назначенных ролей объединяются по OR; пользователь не может самостоятельно обойти обязательное для него правило.

Добровольность не отменяет свежую повторную аутентификацию перед критическими действиями. У администратора без личного фактора в optional-профиле остаются свежий пароль, действующие полномочия, Origin/CSRF и проверки версии. Если фактор подключён либо обязателен, нужен также свежий MFA proof. Отключение личного фактора требует текущего фактора или recovery proof; переключение политики не является восстановлением при потере факторов.

Полный план — [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). Optional-профиль нельзя публиковать до согласованного enforcement для login, SQL authority, management, native/JWT и уже выданных сессий.

## Текущая реализация — A6.3m.1a

Этот подэтап сохраняет прежнее поведение. Новых настроек, API и доступного optional-профиля пока нет. В initial migration выделены две `STABLE`, `SECURITY INVOKER` SQL-функции:

| Правило | Применение | Текущий смысл |
| --- | --- | --- |
| `auth.has_administrative_access(user_id)` | Administrative password intent и лимиты SQL-сессий | System super_admin либо одно из восьми встроенных административных permissions, включая `accounts.users.read` |
| `auth.administrative_mfa_required(user_id)` | MFA status и запрет отключения фактора | System super_admin либо одно из семи управляющих permissions; `accounts.users.read` само по себе сюда не входит |
| `auth.role_requires_mfa(user_id)` | Существующее требование ролей при входе и управлении фактором | Хотя бы одна назначенная роль с `mfa_required=true` |

Первые две функции классифицируют назначения, но не предоставляют полномочия: они не проверяют пароль, действительность сессии или status аккаунта. Эти проверки остаются у вызывающего сценария. SQL вызывается в том же statement и транзакции, без новых round trips, pools, cache или фоновых задач. Функции работают с правами вызывающей DB-роли и не обходят отсутствие SELECT grants.

Не объединяем административные ограничения сессии и запрет отключения MFA в один boolean: это изменило бы поведение read-only администратора. Также наличие личного TOTP, обязательность роли и свежесть proof — самостоятельные гарантии.

Платформенные `operator.AuthorizeRead/AuthorizeMutation` пока сохраняют обязательные password/TOTP guards. Последний usable administrator по-прежнему должен иметь прежние credential prerequisites. Bootstrap, role session revisions, enrollment, native flows и project bridges не ослаблены. Schema изменена в исходной миграции по принятому для текущей разработки правилу; рабочие БД автоматически не меняются.

## Сохранение политики — A6.3m.2a

Подготовлено внутреннее хранение; HTTP-ручек для смены режима пока нет. Значение не применяется к login/authority до следующего этапа полного enforcement. Текущее поведение MFA не ослаблено.

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

Domain-тесты и SQL fixture добавлены для mode validation, прав, no-op, capability denial, конфликтов и конкурентных записей, отката при отказе audit, сохранения роли/фактора и missing-row без seed. Platform fixture проверяет отдельную authority и wrong-realm отказ. Luna V1/V2: Go tests, targeted race, полный Linux ARM64 command SQL, четыре schema-теста, platform operators/MFA settings, operator HTTPS и lint закреплённой v2.14.0 — PASS. Все 17 source hashes совпали со снимком; временные fixtures удалены. HTTP optional profile, first-run выбор режима, работа старых сессий/native/JWT и полная двухпроектная матрица остаются открытыми.

## Дальнейшая реализация

После приёмки внутреннего хранения подключить effective policy ко всем runtime consumers и first-run выбору; существующие установки не должны автоматически ослабляться. Защищённые HTTP-ручки публиковать вместе с согласованным enforcement. Ужесточение должно закрывать обход через старые factorless sessions и pending login, без полного прохода пользователей в горячем пути. Required нельзя включить без готовой capability. Platform MFA readiness не заменяет project MFA readiness.

Проверить оба first-run профиля, изоляцию платформы/проектов, личный фактор в optional-режиме, объединение ролей, freshness, last-admin, конкурентные изменения, native/JWT и recovery. Только после этого публиковать optional API и переходить к UI выбора.

## Проверки подэтапа

Новый `TestMFARequirementPredicatesSchema` проверяет все восемь permissions и обычное продуктовое permission, system administrator, объединение/отзыв ролей и invoker ACL. Существующие SQL-сценарии должны подтвердить сохранение административного login, MFA status/disable, длительностей сессий и platform/project readiness. Luna V1: task check, targeted race и полный Linux ARM64 TestPrepareCommandSQL — PASS. После исправления параметризованных multi-statement запросов в новом fixture Luna V2 подтвердила targeted lint (0 issues) и все шесть schema-тестов в штатном query mode. Все шесть source hashes совпали со снимком и рабочими файлами; временные стенды удалены.
