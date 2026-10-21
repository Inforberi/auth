# Текущий шаг

Обновлено 21 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP3 physical onboarding

Явные Target.ActivateOnboarding/CloseOnboarding связывают restricted catalog admission с maintenance journal и реальным SQL доступом. Opening/open/closing/closed + operation/version/generation; ownership/OIDs/role/ACL guards и target session lock. Withdrawal до target writes; новая runtime authentication перед publication. Close закрывает новые подключения, завершает только project runtime sessions и отмечает closed после drain. Повтор/обрыв executor/старая target epoch восстанавливаются из SQL без reset/adoption. [Контракт](../features/project-onboarding-preparation.md#физическая-активация-и-остановка--21-октября-2026), [проверки/ограничения](../planning/history.md#результат-mp3-physical-onboarding--21-октября-2026).

Restricted executor получает SET TRUE/INHERIT FALSE только к своему runtime (initial schema installer), без pg_signal_backend. Source target SQL/profile расширены без новой migration: старым installations нужен controlled upgrade, не reset. CLI по-прежнему sealed/NOLOGIN; production server/обычные Auth routes/ready/UI не публиковались.

## Следующий шаг — защищённая первоначальная конфигурация

Protected initial SMTP provisioning и доставка setup authority доверенному владельцу, без URL/stdout/platform-secret fallback. Затем trusted loader/dispatcher и automatic reconcile/withdraw/drain при suspend/restart, вызов existing setup, first-admin/configuration readiness → binding/ready. Factory сейчас требует SQL SMTP; runtime activation сама его не создаёт. [План](../planning/multi-project.md#ограничения-runtime-и-onboarding).

Новый протокол пока вызывают только integration tests. Outage/потеря executor может оставить physical open с journal: ошибка cleanup не успех; новый executor обязан reconcile до обслуживания. Catalog unavailable не доказывает withdrawal. Поздний suspend закрывает новые HTTP admission, но не отменяет уже committed project write; background reconcile ещё не реализован. Uncertain commit не означает rollback и не разрешает сбросить данные.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA ещё не реализована, setup/platform guards сохраняются. [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, original PG stopped.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS: точечная навигация и проверки по риску, без повторного обзора проекта/полного suite после мелких правок.
