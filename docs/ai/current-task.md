# Текущий шаг

Обновлено24 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Текущий блок — MP4 resource bounds

[SQL deployment budget и административный admission](../features/platform-resource-bounds.md): configured API instances/surge, public/private catalog/project pool ceilings и external reserve. Local global/actor/project caps без очереди, shared Redis minute budgets для list/read/create/suspend/resume/retry. Общий Lua limiter переиспользован из MFA, её ключи не менялись; SQL authority и session guards сохранены.

Первый отчёт Luna: lint/API/scanner PASS, общий check и router race FAIL на необновлённой fixture Swagger contract. Исправлена только эта fixture, целевой тест PASS. Остальные пакеты race PASS на предыдущем manifest. Live Redis/MFA/operator SQL тогда NOT RUN из-за отсутствующего тега образа; найден установленный redis:8.2-bookworm без pull. На новом снимке Luna сообщила промежуточные PASS полного task check и router race; live Redis/MFA/operator SQL ещё выполняются, финальный gate открыт. Коммит не означает завершение приёмки. [History](../planning/history.md#результат-mp4-resource-bounds--24-октября-2026) содержит первый FAIL и новые snapshot/log paths; не переписывать его как прошлый PASS. Коммит только по запросу. Предыдущий resident sync завершён:802cea6.

## Следующий шаг

Уточнение пользователя: все исполняемые проверки и подготовка стенда — только отдельный чат Luna, включая быстрые tests. Здесь реализация/исправления и подготовка снимка; обратно только ошибки/блокировки, при успехе короткий PASS со snapshot ID, подробности в логах. Основной чат не ждёт. [Правило](development-workflow.md#проверки-параллельно-с-реализацией).

Прочитать компактный результат отдельного чата «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d), устранить только найденные дефекты и повторить затронутые проверки. Затем project-role/read-reconcile concurrency matrix перед role bridge HTTP; остальное — [MP4](../planning/multi-project.md). Scheduler/полная feature assembly/owner-managed readiness/credential rotation ещё открыты. Здесь длинные проверки не ждать и не дублировать.

## Нельзя потерять

- Commit admission до3s — окончательная авторизация конкретной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Poll — resource invalidation, не кеш прав/разрешение stale mutation. Unknown commit не означает rollback; read/reconcile только своей операции при current read authority.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; owner-managed readiness ещё не готова. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup сохраняется.
- UI только после отдельного согласования материалов/стека/макетов: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → UI. Optional MFA и email/Telegram второй фактор пока план; current platform guards остаются. Owner-only deletion ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения. Рабочие БД/ENV/secrets/staging сохранять; старым БД нужен controlled upgrade, init их не обновляет. Go1.27.3 согласован; image build ранее NOT RUN из-за Docker disk — доступность проверять заново, чужое не чистить.
- Source checksum не полный DDL scanner/доверие произвольному серверу. Restore/JWT gates — [приёмка](../operations/acceptance-summary.md). Capacity/GC только по измерениям; local SQL/race не fleet sign-off.
- Следовать [переносимому процессу](development-workflow.md): точечная навигация, независимая параллельная работа, длительные проверки в отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d) на точном снимке. Здесь не ждать и не дублировать успешные несвязанные прогоны.
