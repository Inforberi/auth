# Текущий шаг

Обновлено 21 октября 2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [приёмка](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP3 catalog onboarding admission

Сохраняемый onboarding_admitted по умолчанию false; restricted PermitOnboarding ставит его только после actual SQL runtime probe под current-authority locks. Replay не пишет повторно, Reserve нового epoch сбрасывает grant. Обычный API читает только non-secret metadata, без ciphertext/flag writes. Factory принимает Catalog pool/Reservation и сама создаёт SQL reader вместо внешнего callback; тот проверяется до/после assembly и на каждом setup POST. [Контракт](../features/project-onboarding-preparation.md#сохраняемый-sql-допуск--21-октября-2026).

Task check/lint0, targeted race/security PASS; live PostgreSQL command test PASS1.70s, включая concurrency/rollback/privileges/stale epoch/new Reserve и committed suspend во время assembly. После последнего test-only Reserve case повторены Linux test build/SQL/lint, production code не менялся. [Evidence](../planning/history.md#результат-mp3-catalog-onboarding-admission--21-октября-2026). Initial source catalog/grants расширены без новой migration; старым installations нужен controlled upgrade, не reset. Worker/server/обычные Auth routes/UI не публиковались.

## Следующий шаг — physical onboarding activation/recovery

Сохраняемый target intent/journal → проверка ownership/current authority → controlled LOGIN/CONNECT/open → actual connection/probe → catalog permission, без полного Auth router/ready. Нужны restart/lost-reply/reseal/drain и закрытие admission до отключения physical access; сам permission bit этого не делает. Нынешний CLI оставляет БД sealed и не вызывает PermitOnboarding автоматически. Уже начатый project commit suspend мгновенно не отменяет.

Далее trusted loader/dispatcher, защищённый initial SMTP и доставка setup authority без URL/stdout, first-admin/configuration readiness → binding/ready. [План и ограничения](../planning/multi-project.md#ограничения-runtime-и-onboarding). Failed replay не отзывает прежний grant, uncertain commit требует reconciliation; не трактовать ошибку как доказанный rollback или разрешение сбросить данные.

## Нельзя потерять

- UI — только после отдельного согласования материалов/стека/макетов. MP1–MP6 → MP6R security/refactor → MP7 → MP8 capacity → UI. [План](../planning/multi-project.md), [UI gate](../planning/implementation.md#переход-к-ui--только-после-отдельного-согласования).
- Optional MFA ещё не реализована, setup/platform guards сохраняются. [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7). [Owner-only удаление](../planning/multi-project.md#создание-и-удаление-проектов--уточнение20-октября) — только план, ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости — только с разрешения; рабочие БД/ENV/secrets и staging сохранять. Go1.27.3 согласован ранее, Docker image build не выполнен из-за малого disk; временный tmpfs стенд удалён, original PG stopped.
- Restore/JWT/нагрузка: сначала затронутые [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки)/runbook; local не fleet/production/GC/capacity. Место Docker проверять заново, чужие данные/caches/volumes не чистить.

Следовать AGENTS: точечная навигация и проверки по риску, без повторного обзора проекта/полного suite после мелких правок.
