# Текущий шаг

Обновлено 21 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP2.7 проектная транзакция создания роли

CreatePlatformRoleInTransaction создаёт роль/permissions и append-only project audit/receipt в caller-owned transaction: typed PlatformActor без project user, actual connection identity guard, existing Access lock/shared role insert, permission catalog/MFA capability и no-update replay. Catalog PrepareRoleCreation остаётся отдельной подготовкой. **Связь между ними с current platform authority ещё не подключена**, HTTP/CLI/ENV/dependencies не добавлены. [Контракт](../features/platform-role-intents.md#проектная-транзакция--21-октября-2026), [evidence](../planning/history.md#результат-mp27-project-role-transaction--21-октября-2026). Все Go tests, финальный lint/race/security и actual PostgreSQL18.6 provisioning+project-role suite PASS; 1 прежняя module-only security находка без вызываемого пути. Одноразовый SQL-стенд удалён, рабочие данные не тронуты.

Пользователь уточнил: он как владелец платформы создаёт проекты, управляет каждым и явно добавляет локальных администраторов. Не копировать его identity, не требовать первого local super_admin и не выдавать человеку raw setup token. Это current platform authority через [MP2.7/ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso), не SSO/SQL SUPERUSER/bypass fresh-auth. Standalone setup и прежние закрытые project setup/probe guards не ослаблялись; owner-managed readiness ещё надо реализовать отдельно.

## Следующий шаг — orchestration bridge создания роли

MP2.7 открыт: связать catalog intent с project writer через current platform authority и exact current target/version/generation, полную cold-open schema/grants/checksum аттестацию, guards до commit/rollback, финальный platform outcome и reconciliation uncertain commit по project receipt. Intent/PlatformActor не capability. Проверить revoke/suspend/потерю platform SQL connection во время project write; предварительного чтения недостаточно, HTTP не открывать до этих gates. Далее registry/dispatcher/reconcile и owner-managed readiness → binding/ready. UI отдельно согласовать. [План](../planning/multi-project.md#результат-и-границы).

Ранее подготовленный onboarding протокол пока вызывают только integration tests. Outage/потеря executor может оставить physical open с journal: ошибка cleanup не успех; новый executor обязан reconcile до обслуживания. Catalog unavailable не доказывает withdrawal. Поздний suspend закрывает новые HTTP admission, но не отменяет уже committed project write; background reconcile ещё не реализован. Uncertain commit не означает rollback и не разрешает сбросить данные.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA и выбор email/Telegram второго фактора ещё не реализованы, setup/platform guards сохраняются. [A6.3m.6/A7](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7): allowed/enrolled/preferred методы, независимость primary/second factor и фактический assurance. [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, рабочие контейнеры не менялись.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS: точечная навигация и проверки по риску, без повторного обзора проекта/полного suite после мелких правок.
