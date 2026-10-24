# Текущий шаг

Обновлено 24 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP2.7 SQL runtime profile

Onboarding и actual role transaction используют один SQL identity/version/source-checksum/ACL profile. Private marker доступен runtime только через несекретную SELECT-only view; проверяются её точные колонки/owner, table/view/sequence права и protected exceptions. Grants/revokes атомарны, reapply сохраняет read-only view; source fingerprint общий с installer. [Контракт](../features/project-runtime-profile.md), [evidence](../planning/history.md#результат-mp27-runtime-profile--24-октября-2026). Go tests/финальный lint/race/security и actual PostgreSQL18.6 suite PASS; 1 прежняя module-only security находка. Временный стенд удалён, рабочие данные/ENV не менялись. HTTP/UI/dependencies не добавлены.

Прежний role admission до3s/atomic receipt/outcome сохранён: revoke/suspend запрещает новые допуски, уже допущенная команда может завершиться. Это не обычный session revoke и не distributed transaction. [Role contract](../features/platform-role-intents.md).

Владелец платформы управляет проектами и явно создаёт локальных администраторов без копии identity/обязательного первого local super_admin/raw setup token. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup не ослаблялся; owner-managed readiness ещё открыт.

## Следующий шаг — trusted loader и bounded registry/leases

Подключить trusted target/credential loader и bounded registry/pools/leases с exact binding/generation и profile на реальном соединении. SQL fingerprint не аутентифицирует произвольный сервер/DSN и не заменяет TLS/secret provenance. Затем protected outcome read/reconcile при утрате actor прав, реальные transport faults/admission matrix/resource bounds → HTTP. MP2.7/MP4 целиком открыты; users/access/settings actions ещё отдельные сценарии. Далее dispatcher/reconcile и owner-managed readiness → ready. [План](../planning/multi-project.md#результат-и-границы).

Role orchestration и onboarding пока вызывают только integration tests. Lost-commit-ack — адаптер после настоящего commit, не сетевой/fleet test. Checksum — установленный source marker, не полный DDL-drift scanner. Onboarding outage/reseal ограничения — в [контракте](../features/project-onboarding-preparation.md); unknown commit не означает rollback/reset. Старым БД нужен controlled upgrade, source init их автоматически не обновляет.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA и выбор email/Telegram второго фактора ещё не реализованы, setup/platform guards сохраняются. [A6.3m.6/A7](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7): allowed/enrolled/preferred методы, независимость primary/second factor и фактический assurance. [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, рабочие контейнеры не менялись.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS: точечная навигация и проверки по риску, без повторного обзора проекта/полного suite после мелких правок.
