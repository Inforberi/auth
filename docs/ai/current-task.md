# Текущий шаг

Обновлено 21 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP3 initial project SMTP и уточнение владельца

Target.PrepareSMTP сохраняет explicit project SMTP с project-scoped cipher и atomic private smtp_prepared receipt. Переиспользованы прежние validator/encryption/SQL initializer и executor-only open/reseal. Replay без UPDATE; lost row/orphan/tamper/mismatch/current authority loss дают отказ, не reset/fallback. Новых пользователей/ролей/HTTP/CLI/ENV/dependencies нет. [Контракт](../features/project-onboarding-preparation.md#первоначальный-smtp-проекта--21-октября-2026), [evidence](../planning/history.md#результат-mp3-initial-project-smtp--21-октября-2026).

Пользователь уточнил: он как владелец платформы создаёт проекты, управляет каждым и явно добавляет локальных администраторов. Не копировать его identity, не требовать первого local super_admin и не выдавать человеку raw setup token. Это current platform authority через [MP2.7/ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso), не SSO/SQL SUPERUSER/bypass fresh-auth. Standalone setup и прежние закрытые project setup/probe guards не ослаблялись; owner-managed readiness ещё надо реализовать отдельно.

## Следующий шаг — административный bridge владельца

MP2.7: один platform principal управляет выбранным проектом без fake project user. Сначала конкретный action/permission mapping, удержание current platform authority до project commit, audit actor origin/idempotent receipt/uncertain outcome и revoke/concurrency tests; bridge не открывать до этих guards. Затем trusted registry/dispatcher/automatic reconcile и owner-managed configuration readiness → binding/ready. SMTP нужен выбранным email-функциям, не любому Telegram-only проекту. UI отдельно согласовать. [План](../planning/multi-project.md#результат-и-границы).

Новый протокол пока вызывают только integration tests. Outage/потеря executor может оставить physical open с journal: ошибка cleanup не успех; новый executor обязан reconcile до обслуживания. Catalog unavailable не доказывает withdrawal. Поздний suspend закрывает новые HTTP admission, но не отменяет уже committed project write; background reconcile ещё не реализован. Uncertain commit не означает rollback и не разрешает сбросить данные.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA ещё не реализована, setup/platform guards сохраняются. [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, original PG stopped.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS: точечная навигация и проверки по риску, без повторного обзора проекта/полного suite после мелких правок.
