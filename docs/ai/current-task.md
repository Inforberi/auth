# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Текущий блок — MP2.7 project role assignments

[Контракт](../features/platform-role-assignments.md): opt-in POST grant/revoke обычной роли пользователю; текущие platform AccessManage/password/MFA, browser/session/capacity и exact registry guards. Version checks проекта/роли/user access, cap32, no-op без UPDATE пользователя, active grant отзывает pre-grant sessions, pending сохраняет activation auth_version. System super_admin запрещён в обоих направлениях, старый local last-admin flow сохранён. Revoke допускает blocked non-deleted target; MFA-required grants fail closed до project capability.

Role-family intents/admissions/outcomes переиспользованы, assignment Action хранится в typed immutable request. Общие модели RoleIntent/RoleOutcome названы по фактическим сценариям. Добавлен только project receipt `auth.platform_role_assignments`, updated initial schema/down/grants/profile/checksum; рабочие БД/ENV не менялись и upgrade migration не создавалась. Общая Access persistence отделена от local-user audit, чтобы platform actor не подменял project user. Общие SQL intent/admission и commit boundary выделены внутри role family, универсального execute API нет. Replay completion ссылается на original receipt admission (включая прежнее создание роли).

Добавлены unit/router/domain и реальный HTTPS/SQL drill: counters/sessions/pending/no-op, cap32/system/MFA/unknown target, atomic rollback receipt failure, parallel retries/version conflicts/role edit, receipt recovery без повторного назначения, original admission, local Access audit и last-admin regression. Данные fixture/cleanup только собственные. Root fixture multi-statement mode pgx5.10.0 сверён Context7; runtime protocol не менялся. Formatter/Swagger подготовлены, основной чат **не запускал проверки**. Все tests/race/live SQL/operator/runtime assembly/API/scanner — Luna pending; [history](../planning/history.md#результат-mp27-role-assignments--24-октября-2026) содержит source/evidence после передачи.

## Следующий шаг

Получить итог Luna для V3 `/private/tmp/auth-role-assignment-v3.m6zqqufh`: V2 исправил admission conflict, но assignment fixture не заполнял обязательный sessions.created_at. В V3 исправлен только INSERT двух тестовых сессий; переданы targeted lint и полный actual TLS command SQL, остальные47 source совпадают V2. Все nested assignment cases должны запуститься без SKIP. Итоги V2/V3, прежние PASS и manifest — [history](../planning/history.md#результат-mp27-role-assignments--24-октября-2026). Затем directory/read bridge пользователей/ролей/назначений для получения current versions без догадок, owner-managed readiness и остальные explicit users/settings по плану. Project MFA capability/полная Auth assembly/workers/credential rotation/fleet/RPS/GC ещё открыты. Предыдущий role create API проверен и закоммичен83ef51e.

Все проверки/стенд — Luna, даже быстрые tests. Здесь код/formatter/immutable snapshot; не ждать и не дублировать команды. Коммит только по запросу. UI только после отдельного согласования; отдельные project catalogs/import из backend пока план.

## Нельзя потерять

- Commit admission до3s — окончательная авторизация конкретной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Poll — resource invalidation, не кеш прав/разрешение stale mutation. Unknown commit не означает rollback; read/reconcile только своей операции при current read authority.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; owner-managed readiness ещё не готова. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup сохраняется.
- UI только после отдельного согласования материалов/стека/макетов: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → UI. Optional MFA и email/Telegram второй фактор пока план; current platform guards остаются. Owner-only deletion ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения. Рабочие БД/ENV/secrets/staging сохранять; старым БД нужен controlled upgrade, init их не обновляет. Go1.27.3 согласован; image build ранее NOT RUN из-за Docker disk — доступность проверять заново, чужое не чистить.
- Source checksum не полный DDL scanner/доверие произвольному серверу. Restore/JWT gates — [приёмка](../operations/acceptance-summary.md). Capacity/GC только по измерениям; local SQL/race не fleet sign-off.
- Следовать [переносимому процессу](development-workflow.md): точечная навигация, независимая параллельная работа, длительные проверки в отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d) на точном снимке. Здесь не ждать и не дублировать успешные несвязанные прогоны.
