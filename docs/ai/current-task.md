# Текущий шаг

Обновлено 21 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [открытая приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP3 onboarding runtime foundation

Минимальная factory с borrowed project pool/shared Redis/hasher, независимыми typed keys, SQL role/binding/grants/setup probe и scoped SMTP только из проектной БД. Existing setup и закрытый HTTP-профиль переиспользованы; callback допуска обязателен до/после сборки и на запросах. **К основному серверу не подключено**; production authority/activation не реализована, LOGIN/CONNECT не меняются. [Контракт](../features/project-onboarding-preparation.md#сборка-проектного-runtime--21-октября-2026).

По разрешению пользователя Go обновлён до1.27.3 в go.mod/dev/prod Dockerfile после GO-2026-6809 scanner finding в1.27.2; библиотеки/go.sum не менялись. Task check/lint0, targeted race/security и Linux arm64 build прошли на1.27.3; SQL evidence и ограничения — [history](../planning/history.md#результат-mp3-onboarding-runtime--21-октября-2026). Docker image build/live SMTP/browser/load не выполнены; не выдавать factory за готовый onboarding или deployment.

## Следующий шаг — MP3 activation/admission

Реализовать сохраняемый протокол допуска только onboarding: актуальные reservation/binding/version/generation, actual connection/ACL и suspend/restart/fencing, без открытия обычных Auth endpoints. Нужны доверенный loader/runtime caller, защищённая первоначальная настройка SMTP и доставка setup authority без URL/stdout; затем first-admin/configuration readiness → binding/ready. Нынешний CheckCurrent для offline stages и cold-open probe этого не разрешают. [План и ограничения](../planning/multi-project.md#ограничения-runtime-и-onboarding).

## Нельзя потерять

- UI не начинать автоматически: материалы/стек/макеты и подтверждение отдельно. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → согласованный UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA ещё не реализована; setup/platform MFA guards сохраняются. [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7).
- Owner-only удаление — план; уровень владельца/backup/окончательное удаление ещё согласовать. [Требования](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября).
- PostgreSQL + обязательный Redis, без SQL-only/fallback; namespaces не изолируют ресурсы Redis. Новые зависимости — только с разрешения. Сохранять рабочие БД/ENV/secrets и staging.
- Restore/JWT/нагрузка: сначала затронутые [открытые gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки) и runbook. Локальные проверки не закрывают fleet/production/GC/capacity. Место в Docker перед работой проверить заново; чужие данные/caches/volumes не чистить.

Следовать AGENTS: точечная навигация, нужные контракты/код и достаточная проверка риска. Не повторять обзор проекта/полный suite после каждой мелкой правки.
