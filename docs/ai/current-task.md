# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и стенд проверять по факту.

## Завершённый блок — MP2.7 user directory

Opt-in GET списка пользователей и карточки с текущими ролями/accessVersion. List: UsersManage; detail: UsersManage+AccessManage; current authority/binding до/после readonly snapshot, общий3s deadline. Account validation/cursor/SQL projections/DTO переиспользованы, local SQL actor authority сохранена. Нет новых schema/grants/ENV/dependencies/UI. [Контракт](../features/platform-user-directory.md).

Luna: task check/tests/lint/race/API/security и actual project SQL/local TestUserDirectorySchema PASS. Все обязательные user/role/assignment nested cases без SKIP; manifest81 совпал до/после, cleanup подтверждён. Source перед коммитом совпал с `/private/tmp/auth-user-directory-manifest.sha256`; snapshot `/private/tmp/auth-user-directory.033lrx45`. [Evidence](../planning/history.md#результат-mp27-user-directory--25-октября-2026). Результат относится к этому блоку, не ко всему MP2.7/MP4/fleet.

## Следующий шаг — owner-managed readiness

Уточнить текущий backend протокол готовности проекта и подключить owner-managed readiness: техническая готовность/выбранные функции, без обязательной копии владельца или локального super_admin. Проверять SMTP для выбранных email-сценариев, не искусственно для всех проектов. Связь с activation/runtime и полный Auth/worker assembly выполнять по существующему плану MP3.7/MP4, без публикации небезопасного flow и без UI. Остальные явные user/settings/mutations остаются открытыми; полный MP2.7 не закрывать по завершению read directory.

Все tests/стенд — Luna01a16eab-c777-78a0-a815-47b45ff0860d. Здесь проектирование/код/formatter/snapshot; не ждать и не дублировать проверки. Коммит только по запросу; UI после отдельного согласования.

## Нельзя потерять

- Commit admission до3s — окончательная авторизация конкретной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Poll — resource invalidation, не кеш прав/разрешение stale mutation. Unknown commit не означает rollback; read/reconcile только своей операции при current read authority.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; owner-managed readiness ещё не готова. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup сохраняется.
- UI только после отдельного согласования материалов/стека/макетов: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → UI. Optional MFA и email/Telegram второй фактор пока план; current platform guards остаются. Owner-only deletion ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения. Рабочие БД/ENV/secrets/staging сохранять; старым БД нужен controlled upgrade, init их не обновляет. Go1.27.3 согласован; image build ранее NOT RUN из-за Docker disk — доступность проверять заново, чужое не чистить.
- Source checksum не полный DDL scanner/доверие произвольному серверу. Restore/JWT gates — [приёмка](../operations/acceptance-summary.md). Capacity/GC только по измерениям; local SQL/race не fleet sign-off.
- Следовать [переносимому процессу](development-workflow.md): точечная навигация, независимая параллельная работа, длительные проверки в отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d) на точном снимке. Здесь не ждать и не дублировать успешные несвязанные прогоны.
