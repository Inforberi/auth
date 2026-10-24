# Текущий шаг

Обновлено24 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP2.7 role concurrency

[Матрица](../operations/platform-role-faults.md#дополнение-команды-ролей-и-восстановление-результата) проверена Luna: task check, command host race и actual PostgreSQL TLS suite PASS; новые сценарии выполнены, fixture очищен, hashes совпали до/после. Snapshot `/private/tmp/auth-role-concurrency-snapshot.xg_rpbaz`, manifest5 Go совпал и с рабочим кодом перед коммитом. [Evidence](../planning/history.md#результат-mp27-role-concurrency--24-октября-2026).

Проверены one-use Execute, разные operations/один role key, local Access writer commit/rollback, revoke session/read/TOTP/auth_version во время receipt read, допустимое чтение после write revoke/suspend и parallel reconciliation без новых admissions/перезаписи receipt. Production code/schema/routes/dependencies не менялись. Предыдущая очистка operator fixture уже проверена V3 resource bounds actual SQL/HTTPS PASS и входит в отдельный коммит. Текущие commit/staging смотреть через Git.

## Следующий шаг

Оценить оставшиеся prerequisites и подключить role bridge HTTP с existing platform guard/admission/receipt/outcome/registry, browser protection и resource admission. Новые маршруты не открывать до готовности нужной сборки/guards. Полный MP2.7/MP4, scheduler/полная feature assembly/owner-managed readiness/credential rotation/fleet/RPS/GC остаются открытыми.

Все исполняемые проверки и стенд — отдельный чат Luna01a16eab-c777-78a0-a815-47b45ff0860d, включая быстрые tests; сюда только ошибки/блокировки или короткий PASS со snapshot ID. Здесь не ждать и не дублировать прогоны. [Правило](development-workflow.md#проверки-параллельно-с-реализацией). Коммит только по запросу, сохранять пользовательские изменения/staging.

## Нельзя потерять

- Commit admission до3s — окончательная авторизация конкретной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Poll — resource invalidation, не кеш прав/разрешение stale mutation. Unknown commit не означает rollback; read/reconcile только своей операции при current read authority.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; owner-managed readiness ещё не готова. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup сохраняется.
- UI только после отдельного согласования материалов/стека/макетов: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → UI. Optional MFA и email/Telegram второй фактор пока план; current platform guards остаются. Owner-only deletion ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения. Рабочие БД/ENV/secrets/staging сохранять; старым БД нужен controlled upgrade, init их не обновляет. Go1.27.3 согласован; image build ранее NOT RUN из-за Docker disk — доступность проверять заново, чужое не чистить.
- Source checksum не полный DDL scanner/доверие произвольному серверу. Restore/JWT gates — [приёмка](../operations/acceptance-summary.md). Capacity/GC только по измерениям; local SQL/race не fleet sign-off.
- Следовать [переносимому процессу](development-workflow.md): точечная навигация, независимая параллельная работа, длительные проверки в отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d) на точном снимке. Здесь не ждать и не дублировать успешные несвязанные прогоны.
