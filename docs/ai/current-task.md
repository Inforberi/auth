# Текущий шаг

Обновлено 20 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [открытая приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту, не по прошлым заметкам.

## Последний функциональный результат

MP3-onboarding-http-profile: отдельный handler только для setup/start и setup/complete, exact HTTPS/Host/Origin, обязательный current-admission callback, без обычных Auth routes. **К серверу не подключён**; project БД sealed/runtime NOLOGIN. [Контракт](../features/project-onboarding-preparation.md#изолированный-http-профиль-onboarding), [проверки](../planning/history.md#результат-mp3-onboarding-http-profile--20-октября-2026): task check/lint0, targeted race/security PASS; live SQL/SMTP/browser этим блоком не проверялись.

Текущий рабочий блок — только сокращение навигационных документов и уточнение порядка работы; функциональный этап не продвинут. Подробности и проверка ссылок — [history](../planning/history.md#результат-навигация-и-контекст--20-октября-2026).

## Следующий функциональный шаг — MP3 runtime/onboarding

Минимальная сборка с project SQL pool, собственными ключами и SQL SMTP, без fallback на platform secrets и без полного Auth router. Затем actual runtime/grants probe, production admission/fencing и безопасная доставка setup authority; first-admin/configuration readiness → binding/ready. [План и обязательные ограничения](../planning/multi-project.md#ограничения-runtime-и-onboarding), [контракт подготовки](../features/project-onboarding-preparation.md). Не объявлять snapshot/marker разрешением открыть runtime.

## Нельзя потерять

- UI **не начинать автоматически**: отдельно согласовать материалы/стек/макеты и получить подтверждение. Порядок: MP1–MP6 → MP6R security review/рефакторинг → MP7 → MP8 capacity → согласованный UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA пока **не реализована**; действующие setup/platform MFA guards сохраняются. [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7).
- Owner-only удаление — только план; уровень владельца/backup/окончательное удаление ещё согласовать. [Требования](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября).
- PostgreSQL + обязательный Redis, без SQL-only/fallback; namespaces не изолируют ресурсы общего Redis. Новые зависимости — только с явного разрешения. Код/БД/ENV/секреты и staging сохранять.
- При работах с restore/JWT/нагрузкой сначала читать соответствующие [открытые gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки) и профильный runbook. Прежние локальные проверки не закрывают fleet/production/GC/capacity.

Дальнейшая работа — по AGENTS: точечный поиск → нужные контракты/код → достаточная проверка риска. Не повторять обзор проекта или весь набор проверок после каждой мелкой правки.
