# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1a project Auth loader

[Решение и контракт](../features/project-auth-loader.md). Добавлены узкий AuthKey и read-only LoadAuthConfiguration: общий с DB loader exact catalog/profile SQL, AEAD binding, stored policy через readonly RepeatableRead под существующим registry lease, финальная проверка current key. Не выдаются DB password/setup/signing; fmt/JSON скрывают объект. Общий timeout3s; нет ENV fallback/Initialize/новых pools/routes/workers/capabilities. На ошибке нет частичного результата.

Luna V1 task check/affected race PASS; V2 полный actual TestPrepareCommandSQL PASS без SKIP, включая loader и четыре subtests, runtime/roles/onboarding/managed и parent replay/wrong-root. Targeted lint cmd/project-prepare PASS (0 issues). Manifest7 совпал до/после и main перед коммитом. Snapshot `/private/tmp/auth-project-loader-v2.taex8bqe`, base515f62c, manifest `/private/tmp/auth-project-loader-v2-manifest.sha256`, metadata `/private/tmp/auth-project-loader-v2-snapshot.json`. Ownfixture удалена; [evidence](../planning/history.md#результат-mp41a-project-auth-loader--25-октября-2026). Пользователь разрешил commit и следующий блок.

## Следующий шаг

MP4.1b: собрать существующие feature services для selected project с project data key/scope и сохранёнными settings, без ENV auto-seed и дополнительных pools. Важно: registry callback выдаёт leased connection, его нельзя сохранить в realm/services/workers после callback. Полный Auth runtime lifecycle требует явного решения reuse/leases/eviction и bounded workers; не подменять это скрытым pool или global current project.

Loader — assembly snapshot, не admission/cache/public-ready. Проверка actual delivery/providers/token dependencies и policy version перед serving остаётся далее; current settings bridge capabilities пусты. Managed provisioning/ready publication имеет отдельные stage guards, normal loader допускает только ready/enabled. Existing sessions/JWT policy автоматически не отзывает.

## Нельзя потерять

- Предыдущий блок515f62c project Auth policy: Luna V1–V5 PASS, full command SQL без SKIP; [evidence](../planning/history.md#результат-mp27-project-auth-policy--25-октября-2026). Source68 совпал перед коммитом. Controlled upgrade initial schema/grants — отдельная операция, рабочие БД не менялись.
- Committed admission до3s — окончательная авторизация точной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Unknown commit не означает rollback. Owner не копируется в project users; standalone setup сохраняется.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения; здесь не добавлены. Реальные БД/ENV/secrets/staging сохранять. Go1.27.3 согласован.
- До UI: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → отдельно согласованный UI. Перед UI заранее предупредить и согласовать переход/стек/макеты/экраны. Frontend сейчас не начинать. Capacity/GC/fleet только по измерениям.
- Все tests/fixtures в отдельном чате «Проверки Auth — Luna», exact snapshot/cwd обязателен: worktree6377/auth — другой stale проект. Здесь не ждать/не дублировать. [Процесс](development-workflow.md).
