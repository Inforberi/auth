# Текущий шаг

Обновлено 24 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP4 local runtime lifecycle

Luna завершила проверку: Go tests/race/security/command TLS SQL и новый assembly SQL PASS; первоначальный `task check` FAIL на4 lint issues, после исправления targeted lint0/parser/runtime race PASS. Полный task check повторно не запускался и не переименован в PASS. Все19 изменённых Go совпали с verified manifest `/private/tmp/auth-runtime-lifecycle-fix-manifest.sha256`. [Evidence](../planning/history.md#результат-mp4-local-runtime-lifecycle--24-октября-2026). Новый код завершён; commit/staging проверять через Git.

[Опциональная assembly](../features/project-runtime-lifecycle.md): отдельный read-only catalog pool/codec/trusted target и bounded registry, startup/readiness profile, confirmed lifecycle receipt → local retirement старых snapshots, active lease/drain до закрытия catalog dependencies. Fleet invalidation и credential rotation не добавлены. Новые ENV только в examples, default false; реальные данные/ENV не менялись, HTTP role bridge закрыт.

Длительные проверки выполнял отдельный чат «Проверки Auth — Luna» (`01a16eab-c777-78a0-a815-47b45ff0860d`); здесь они не дублировались. SQL startup/readiness/unsafe-grant refusal/failed-start cleanup и отсутствие private sessions после shutdown проверены, без SKIP. Контейнеры/cert/binaries убраны Luna; логи/manifest сохранены. Новых HTTP routes/schema/dependencies нет.

Предыдущая [authority/transport матрица](../operations/platform-role-faults.md) уже проверена Luna: task check/lint0/command race и actual TLS SQL PASS9.54s, все новые cases без SKIP. [Evidence](../planning/history.md#результат-mp27-authoritytransport--24-октября-2026). Test changes вошли в `45ad468`; эту приёмку не путать с новой assembly. Текущий Git/staging проверять по факту.

## Последний завершённый блок — protected role outcomes

[Read-own/reconcile](../features/platform-role-outcomes.md): current ProjectsRead и fresh proofs, только своя операция; потеря write permission не выдаёт новый admission и не стирает известный результат. Recovery читает exact project receipt в read-only transaction, сверяет admission, дописывает completion evidence и снова проверяет доступ перед выдачей. Missing receipt остаётся unknown, не rollback.

Outcome коммит `e69bc71`, прежние `94f1ea6` workflow / `fa901fb` registry; текущий Git/staging проверять по факту. Outcome tests/lint/race/TLS SQL PASS, [evidence](../planning/history.md#результат-mp27-role-outcomes--24-октября-2026). Новая authority/transport матрица этим прошлым PASS не подтверждается.

Используется прежний [trusted SQL registry](../features/project-runtime-registry.md) с binding/version/generation/lease/budgets и actual connection profile. Commit admission до3s остаётся окончательной авторизацией: revoke/suspend запрещает новые допуски, уже допущенная команда может завершиться. Обычный session revoke не меняется. [Role contract](../features/platform-role-intents.md).

Владелец платформы управляет проектами и явно создаёт локальных администраторов без копии identity/обязательного первого local super_admin/raw setup token. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup не ослаблялся; owner-managed readiness ещё открыт.

## Следующий шаг — межэкземплярный invalidation и resource bounds

Определить механизм доставки/восстановления lifecycle changes между API instances: SQL остаётся authority, потеря уведомления не должна оставлять бесконечный stale runtime. Не вводить broker/универсальный event framework без необходимости. Затем согласованные fleet/resource/rate bounds, недостающая project-role/read-reconcile concurrency matrix и role bridge HTTP. Полная Auth feature assembly/worker scheduler/owner-managed readiness и другие users/access/settings actions остаются открытыми. Полностью отозванному/другому оператору outcome по UUID не выдаётся. MP2.7/MP4 целиком не закрыты. [План](../planning/multi-project.md#результат-и-границы).

Role orchestration и onboarding пока вызывают только integration tests. Lost-commit-ack — адаптер после настоящего commit, не сетевой/fleet test. Checksum — установленный source marker, не полный DDL-drift scanner. Onboarding outage/reseal ограничения — в [контракте](../features/project-onboarding-preparation.md); unknown commit не означает rollback/reset. Старым БД нужен controlled upgrade, source init их автоматически не обновляет.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA и выбор email/Telegram второго фактора ещё не реализованы, setup/platform guards сохраняются. [A6.3m.6/A7](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7): allowed/enrolled/preferred методы, независимость primary/second factor и фактический assurance. [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, рабочие контейнеры не менялись.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS и [переносимому процессу](development-workflow.md): точечная навигация, обычный runner, помощник по необходимости и независимая параллельная работа. Проверки относятся к точному снимку кода; не повторять успешные несвязанные проверки и полный suite после мелких правок.
