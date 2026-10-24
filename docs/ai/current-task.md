# Текущий шаг

Обновлено 24 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP2.7 trusted SQL registry

[Реестр](../features/project-runtime-registry.md) использует configured targets/TLS/SCRAM, отдельный SELECT-only catalog credential reader и exact binding/version/generation. Пулы переиспользуются с resident/connection/acquiring bounds, single-flight, callback lease, idle eviction/invalidation и bounded shutdown; active lease не закрывается, closing slot остаётся в бюджете. Каждый physical connect проходит SQL profile, role ExecuteWithRuntime сохраняет actual-transaction проверку и admission deadline.

Formatter/полный task check lint0, финальные targeted race/lint/security и actual PostgreSQL18.6 TLS suite PASS9.05s. 1 прежняя module-only security находка. [Evidence](../planning/history.md#результат-mp27-runtime-registry--24-октября-2026). Temporary SQL/TLS fixture удалён, рабочие данные/ENV не менялись. HTTP/dependencies/новые миграции не добавлены; production assembly не подключена.

Прежний role admission до3s/atomic receipt/outcome сохранён: revoke/suspend запрещает новые допуски, уже допущенная команда может завершиться. Это не обычный session revoke и не distributed transaction. [Role contract](../features/platform-role-intents.md).

Владелец платформы управляет проектами и явно создаёт локальных администраторов без копии identity/обязательного первого local super_admin/raw setup token. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup не ослаблялся; owner-managed readiness ещё открыт.

## Следующий шаг — protected outcome read/reconcile

Определить и реализовать защищённое чтение/reconcile результата уже допущенной role операции при утрате исходным actor прав, без повторной мутации/продления admission и без выдачи чужого результата. Дальше production wiring/автоматический invalidation, реальные transport-fault/concurrent suspend-factor-role matrix и fleet/rate/resource budgets → HTTP. Полная Auth feature assembly/worker scheduler/owner-managed readiness и остальные users/access/settings actions остаются открытыми. MP2.7/MP4 целиком не закрыты. [План](../planning/multi-project.md#результат-и-границы).

Role orchestration и onboarding пока вызывают только integration tests. Lost-commit-ack — адаптер после настоящего commit, не сетевой/fleet test. Checksum — установленный source marker, не полный DDL-drift scanner. Onboarding outage/reseal ограничения — в [контракте](../features/project-onboarding-preparation.md); unknown commit не означает rollback/reset. Старым БД нужен controlled upgrade, source init их автоматически не обновляет.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA и выбор email/Telegram второго фактора ещё не реализованы, setup/platform guards сохраняются. [A6.3m.6/A7](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7): allowed/enrolled/preferred методы, независимость primary/second factor и фактический assurance. [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, рабочие контейнеры не менялись.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS и [переносимому процессу](development-workflow.md): точечная навигация, обычный runner, помощник по необходимости и независимая параллельная работа. Проверки относятся к точному снимку кода; не повторять успешные несвязанные проверки и полный suite после мелких правок.
