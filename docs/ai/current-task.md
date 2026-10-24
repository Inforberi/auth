# Текущий шаг

Обновлено24 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP2.7 role HTTP bridge

[Контракт](../features/platform-roles-api.md): opt-in POST project roles, GET own operation, POST reconcile. Прежние prepare/admission/ExecuteWithRuntime/receipt/outcome и browser/session/resource guards; project UUID включён в SQL scope до runtime borrowing. New MFA-required roles fail closed до реальной project capability. Каталог — trusted deployment ACCESS_CATALOG_FILE; independent project catalogs/settings ещё отдельно. UI не начинали.

Luna V1: tests/race/actual HTTP command TLS SQL/operator SQL/API/scanner PASS; task check FAIL только3 lint. Исправлены extraction readiness/routes в тех же файлах и promoted method; V2 targeted lint/race PASS,24 hashes совпали до/после и с рабочим кодом перед коммитом. Новый полный task check не повторялся без причины; финальные lint/check статусы описаны точно в [history](../planning/history.md#результат-mp27-role-http--24-октября-2026). Финальный snapshot `/private/tmp/auth-role-http-v2-snapshot.w6c831su`. Commit/staging смотреть Git.

## Следующий шаг

Следующие explicit users/assignments/settings bridge и owner-managed readiness по [multi-project](../planning/multi-project.md), не универсальный execute. Подключить фактическую project MFA capability вместе с project Auth assembly, не operator config. Согласованное направление: единый API для будущего UI/интеграций, ручные роли и trusted backend permission catalogs; импорт Swagger сам не назначает доступ. Полный MP2.7/MP4, scheduler/credential rotation/fleet/RPS/GC остаются открытыми.

Все проверки/стенд — Luna01a16eab-c777-78a0-a815-47b45ff0860d, даже быстрые tests. Здесь реализация/исправления/formatter и immutable snapshot; не ждать и не дублировать прогоны. Коммит только по запросу. UI только после отдельного согласования.

## Нельзя потерять

- Commit admission до3s — окончательная авторизация конкретной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Poll — resource invalidation, не кеш прав/разрешение stale mutation. Unknown commit не означает rollback; read/reconcile только своей операции при current read authority.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; owner-managed readiness ещё не готова. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup сохраняется.
- UI только после отдельного согласования материалов/стека/макетов: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → UI. Optional MFA и email/Telegram второй фактор пока план; current platform guards остаются. Owner-only deletion ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения. Рабочие БД/ENV/secrets/staging сохранять; старым БД нужен controlled upgrade, init их не обновляет. Go1.27.3 согласован; image build ранее NOT RUN из-за Docker disk — доступность проверять заново, чужое не чистить.
- Source checksum не полный DDL scanner/доверие произвольному серверу. Restore/JWT gates — [приёмка](../operations/acceptance-summary.md). Capacity/GC только по измерениям; local SQL/race не fleet sign-off.
- Следовать [переносимому процессу](development-workflow.md): точечная навигация, независимая параллельная работа, длительные проверки в отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d) на точном снимке. Здесь не ждать и не дублировать успешные несвязанные прогоны.
