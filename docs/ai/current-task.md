# Текущий шаг

Обновлено 21 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP2.7 подготовка создания роли

PrepareRoleCreation сохраняет только catalog intent/audit: current locked AccessManage authority, exact project/version/generation/storage binding, canonical request и неизменяемый replay без UPDATE. Роль в проектной БД **не создаётся**; новых HTTP/CLI/ENV/dependencies нет. [Контракт](../features/platform-role-intents.md), [evidence](../planning/history.md#результат-mp27-role-intent-foundation--21-октября-2026). Formatter/task check/targeted lint/tests/race/security и actual PostgreSQL18.6 suite PASS; 1 прежняя module-only security находка без вызываемого пути. Временный SQL-стенд удалён, рабочие данные не тронуты. Прежний SMTP результат сохранён в history/feature docs.

Пользователь уточнил: он как владелец платформы создаёт проекты, управляет каждым и явно добавляет локальных администраторов. Не копировать его identity, не требовать первого local super_admin и не выдавать человеку raw setup token. Это current platform authority через [MP2.7/ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso), не SSO/SQL SUPERUSER/bypass fresh-auth. Standalone setup и прежние закрытые project setup/probe guards не ослаблялись; owner-managed readiness ещё надо реализовать отдельно.

## Следующий шаг — выполнение создания роли через bridge

MP2.7 открыт: typed platform actor в конкретном project role creation, реальная connection attestation, project mutation/audit/receipt в одной transaction, удержание current authority до результата и reconciliation uncertain commit. Intent не capability/очередь/разрешение отложенного исполнения. Проверить revoke/suspend/потерю platform SQL connection во время project write; HTTP не открывать до этих gates. Далее registry/dispatcher/reconcile и owner-managed readiness → binding/ready. UI отдельно согласовать. [План](../planning/multi-project.md#результат-и-границы).

Ранее подготовленный onboarding протокол пока вызывают только integration tests. Outage/потеря executor может оставить physical open с journal: ошибка cleanup не успех; новый executor обязан reconcile до обслуживания. Catalog unavailable не доказывает withdrawal. Поздний suspend закрывает новые HTTP admission, но не отменяет уже committed project write; background reconcile ещё не реализован. Uncertain commit не означает rollback и не разрешает сбросить данные.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA и выбор email/Telegram второго фактора ещё не реализованы, setup/platform guards сохраняются. [A6.3m.6/A7](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7): allowed/enrolled/preferred методы, независимость primary/second factor и фактический assurance. [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, рабочие контейнеры не менялись.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS: точечная навигация и проверки по риску, без повторного обзора проекта/полного suite после мелких правок.
