# Текущий шаг

2 ноября 2026. R3 принят Luna на неизменяемом снимке `/private/tmp/auth-r3-full-v7-j90m_67o`: manifest749 без расхождений, `task check` (tests/lint0), затронутые race, `check:api` и все семь запрошенных SQL roots — PASS. Main сверил исходники со снимком; executable checks не повторял. Evidence: `/private/tmp/auth-r3-full-v7-results-summary.log`, [приёмка](../operations/acceptance-summary.md#r3-итоговая-приёмка--2-ноября-2026).

Упорядочены admin/administrators/projects, подфичи roles/directory/policy/preparation/runtime, сборка app/admin и app/projects/preparation, тонкий cmd/project-prepare, миграции auth/admin и tests у владельцев. API, SQL-схема platform, permission strings, crypto scopes и шесть SQL-файлов сохранены. Новых зависимостей и функций нет.

Следующий шаг — R4 MFA по [плану рефакторинга](../planning/readability-refactor.md). UI не начинать. R2 закоммичен:6429cde; его live readiness/TestPrepareJWT остаются NOT RUN: чужой auth-sandbox не трогать. R3 не закрывает внешние, MP7/MP8, capacity/GC и остальные gates.

Рабочие env/БД/secrets не менять. Все executable checks — отдельному Luna; новые dependencies требуют разрешения. Коммиты/staging сверять через Git.
