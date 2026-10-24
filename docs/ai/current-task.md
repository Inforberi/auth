# Текущий шаг

Обновлено 24 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP2.7 role admission

Внутренняя SQL-связка intent → committed admission до3s → project receipt → catalog outcome реализована. Пользователь согласовал границу: revoke/suspend запрещает новые допуски; уже окончательно допущенная команда может завершиться в коротком окне. Это не изменение обычного session revoke и не distributed transaction. One-use включает копии Go-объекта; unknown commit и потерянный catalog outcome восстанавливаются через новый current admission и receipt. [Контракт](../features/platform-role-intents.md#окончательный-допуск-и-выполнение--24-октября-2026), [evidence](../planning/history.md#результат-mp27-role-admission--24-октября-2026). Task check/lint/race/security и actual PostgreSQL18.6 SQL suites PASS; 1 прежняя module-only security находка. Временный стенд/binaries удалены, рабочие данные не менялись. HTTP/CLI/UI/dependencies не добавлены.

Владелец платформы управляет проектами и явно создаёт локальных администраторов без копии identity/обязательного первого local super_admin/raw setup token. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup не ослаблялся; owner-managed readiness ещё открыт.

## Следующий шаг — trusted project runtime перед HTTP

Подключить registry/lease и полную cold-open schema/grants/checksum аттестацию exact current binding, не публиковать Execute с произвольным pool/DSN. Затем protected outcome read/reconcile при утрате исходным actor прав, реальные transport faults и concurrent admission/suspend/role/factor checks, resource bounds → HTTP. MP2.7 целиком открыт; другие users/access/settings actions ещё отдельные сценарии. Далее dispatcher/reconcile и owner-managed readiness → ready. [План](../planning/multi-project.md#результат-и-границы).

Оба протокола пока вызывают только integration tests. Lost-commit-ack test — адаптер после настоящего commit, не сетевой/fleet test. Onboarding outage/reseal ограничения и background recovery — в [контракте](../features/project-onboarding-preparation.md); неизвестный commit не означает rollback/reset.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA и выбор email/Telegram второго фактора ещё не реализованы, setup/platform guards сохраняются. [A6.3m.6/A7](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7): allowed/enrolled/preferred методы, независимость primary/second factor и фактический assurance. [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, рабочие контейнеры не менялись.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS: точечная навигация и проверки по риску, без повторного обзора проекта/полного suite после мелких правок.
