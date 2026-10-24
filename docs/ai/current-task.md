# Текущий шаг

Обновлено24 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и доступность стенда проверять по факту.

## Последний результат — MP4 resident sync

[Периодическая сверка](../features/project-runtime-sync.md): только resident/opening keys, batches128/общий deadline, empty registry без SQL. Error/incomplete/expired evidence retiring, active lease сохранена, stale response не закрывает replacement entry. Один worker на registry, cancel/join перед private catalog close. Общий binding predicate с cold loader, без ciphertext/decryption на poll; новые ENV5s/2s, runtime default off.

Luna: task check/lint0, host race, actual PostgreSQL TLS command regression с новым sync scenario и assembly SQL PASS без SKIP. Все13 Go совпали с manifest перед коммитом; [evidence](../planning/history.md#результат-mp4-resident-sync--24-октября-2026). Логи/manifest сохранены, временный стенд удалён Luna, рабочие ENV/БД не менялись. Scanner не повторяли без изменения dependencies/transport/crypto/grants. Это два registry в одном процессе, не fleet/partition/capacity/GC приёмка. Блок завершён, текущий commit/staging смотреть через Git.

Предыдущая [local assembly/lifecycle](../features/project-runtime-lifecycle.md) — commit569a098; [authority/socket faults](../operations/platform-role-faults.md) —45ad468; [protected role outcomes](../features/platform-role-outcomes.md) —e69bc71. Старые lint FAIL/targeted fixes сохранены в history, не переписаны как прошлый full PASS.

## Следующий шаг — общие resource/rate bounds

Согласовать и реализовать общий бюджет SQL/catalog/worker resources по API instances и ограничение administrative admission, сохраняя существующие Redis/SQL guarantees. Не добавлять broker/универсальный workflow. Далее недостающая project-role/read-reconcile concurrency matrix, role bridge HTTP и остальные users/access/settings actions. Полная Auth feature assembly/worker scheduler/owner-managed readiness, credential rotation и весь MP4 ещё открыты. [План](../planning/multi-project.md).

## Нельзя потерять

- Commit admission до3s — окончательная авторизация конкретной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Poll — resource invalidation, не кеш прав/разрешение stale mutation. Unknown commit не означает rollback; read/reconcile только своей операции при current read authority.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; owner-managed readiness ещё не готова. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup сохраняется.
- UI только после отдельного согласования материалов/стека/макетов: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → UI. Optional MFA и email/Telegram второй фактор пока план; current platform guards остаются. Owner-only deletion ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения. Рабочие БД/ENV/secrets/staging сохранять; старым БД нужен controlled upgrade, init их не обновляет. Go1.27.3 согласован; image build ранее NOT RUN из-за Docker disk — доступность проверять заново, чужое не чистить.
- Source checksum не полный DDL scanner/доверие произвольному серверу. Restore/JWT gates — [приёмка](../operations/acceptance-summary.md). Capacity/GC только по измерениям; local SQL/race не fleet sign-off.
- Следовать [переносимому процессу](development-workflow.md): точечная навигация, независимая параллельная работа, длительные проверки в отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d) на точном снимке. Здесь не ждать и не дублировать успешные несвязанные прогоны.
