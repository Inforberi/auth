# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и стенд проверять по факту.

## Завершённый блок — MP2.7 role directory

GET списка ролей с keyset pagination и карточки с permissions/system/version, exact target/version/generation и current AccessManage/fresh-auth до/после readonly project snapshot. [Контракт](../features/platform-role-directory.md). Нет новых schema/ENV/dependencies/UI. Luna: V1 tests/actual TLS SQL/race/API/security PASS; оба formatter замечания закрыты targeted V2 lint PASS, manifest59 совпал до/после. Все assignment nested SQL cases тоже прошли без SKIP: прежний SQL gate закрыт. Evidence/source/исходные FAIL — [history](../planning/history.md#результат-mp27-role-directory--25-октября-2026). Полный MP2.7/MP4/fleet не закрыт.

## Следующий шаг — user directory/read bridge

Добавить список пользователей с точными email/status фильтрами и keyset pagination, карточку с текущими назначениями/accessVersion. Переиспользовать account validation/cursor и SQL projections, не подделывать project actor. Владелец SQL — account repository; typed platform authority отдельно. До выдачи данных повторять current permissions и exact binding; PII не раскрывать по одному ProjectsRead. Luna ищет точки минимального переиспользования, без правок/новых тестов; основной агент проектирует и реализует.

Все tests/стенд — Luna01a16eab-c777-78a0-a815-47b45ff0860d, не ждать и не дублировать команды. Коммит только по запросу. UI только после отдельного согласования. Owner readiness/project capability/full Auth assembly остаются следующими этапами.

## Нельзя потерять

- Commit admission до3s — окончательная авторизация конкретной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Poll — resource invalidation, не кеш прав/разрешение stale mutation. Unknown commit не означает rollback; read/reconcile только своей операции при current read authority.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; owner-managed readiness ещё не готова. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup сохраняется.
- UI только после отдельного согласования материалов/стека/макетов: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → UI. Optional MFA и email/Telegram второй фактор пока план; current platform guards остаются. Owner-only deletion ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения. Рабочие БД/ENV/secrets/staging сохранять; старым БД нужен controlled upgrade, init их не обновляет. Go1.27.3 согласован; image build ранее NOT RUN из-за Docker disk — доступность проверять заново, чужое не чистить.
- Source checksum не полный DDL scanner/доверие произвольному серверу. Restore/JWT gates — [приёмка](../operations/acceptance-summary.md). Capacity/GC только по измерениям; local SQL/race не fleet sign-off.
- Следовать [переносимому процессу](development-workflow.md): точечная навигация, независимая параллельная работа, длительные проверки в отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d) на точном снимке. Здесь не ждать и не дублировать успешные несвязанные прогоны.
