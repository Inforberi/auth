# Текущий шаг

Обновлено 24 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP2.7 protected role outcomes

[Read-own/reconcile](../features/platform-role-outcomes.md): current ProjectsRead и fresh proofs, только своя операция; потеря write permission не выдаёт новый admission и не стирает известный результат. Recovery читает exact project receipt в read-only transaction, сверяет admission, дописывает completion evidence и снова проверяет доступ перед выдачей. Missing receipt остаётся unknown, не rollback.

Предыдущие коммиты: `94f1ea6` workflow, `fa901fb` registry. Outcome блок завершён; текущий commit/staging проверять через Git. Luna на отдельном snapshot: task check/lint0/race и SQL TLS suite PASS9.01s; найден и исправлен OID JSON mismatch, после него повторены только затронутые проверки. Snapshot совпал с Go в рабочем дереве; временные стенд/сертификаты/снимок удалены. [Evidence](../planning/history.md#результат-mp27-role-outcomes--24-октября-2026). HTTP/dependencies/миграций нет, рабочие данные/ENV не менялись.

Используется прежний [trusted SQL registry](../features/project-runtime-registry.md) с binding/version/generation/lease/budgets и actual connection profile. Commit admission до3s остаётся окончательной авторизацией: revoke/suspend запрещает новые допуски, уже допущенная команда может завершиться. Обычный session revoke не меняется. [Role contract](../features/platform-role-intents.md).

Владелец платформы управляет проектами и явно создаёт локальных администраторов без копии identity/обязательного первого local super_admin/raw setup token. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup не ослаблялся; owner-managed readiness ещё открыт.

## Следующий шаг — реальные отказы и concurrent authority matrix

Проверить новую registry/admission/outcome связку при фактическом разрыве подключения и конкурентном revoke/suspend/factor/role change; различать known commit, unknown и безопасный отказ. Дальше production wiring/автоматический invalidation и fleet/rate/resource budgets → HTTP. Полная Auth feature assembly/worker scheduler/owner-managed readiness и остальные users/access/settings actions остаются открытыми. Полностью отозванному/другому оператору outcome по UUID не выдаётся. MP2.7/MP4 целиком не закрыты. [План](../planning/multi-project.md#результат-и-границы).

Role orchestration и onboarding пока вызывают только integration tests. Lost-commit-ack — адаптер после настоящего commit, не сетевой/fleet test. Checksum — установленный source marker, не полный DDL-drift scanner. Onboarding outage/reseal ограничения — в [контракте](../features/project-onboarding-preparation.md); unknown commit не означает rollback/reset. Старым БД нужен controlled upgrade, source init их автоматически не обновляет.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA и выбор email/Telegram второго фактора ещё не реализованы, setup/platform guards сохраняются. [A6.3m.6/A7](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7): allowed/enrolled/preferred методы, независимость primary/second factor и фактический assurance. [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, рабочие контейнеры не менялись.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS и [переносимому процессу](development-workflow.md): точечная навигация, обычный runner, помощник по необходимости и независимая параллельная работа. Проверки относятся к точному снимку кода; не повторять успешные несвязанные проверки и полный suite после мелких правок.
