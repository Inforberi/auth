# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1d project SMTP

[Контракт](../features/project-smtp-runtime.md). Добавлен NewProjectMailer: existing settings/mail transport, project data key, scoped Redis и trusted allowlist; Credentials под UsePool/current guards, network после освобождения lease. Сохранённые настройки проверяются при сборке и перечитываются перед отправкой. Нет Initialize/ENV fallback/new deps/schema/pool/worker/public route/readiness. Без SMTP password/TOTP работают независимо; email consumer получает явный отказ сборки.

Добавлен actual SQL fixture projectSMTPDrill в TestPrepareCommandSQL: no-init, scoped decrypt, allowlist clone, unchanged xmin, refresh/rejection/missing/corrupt/TLS, suspend, free single SQL connection during SMTP I/O и отсутствие Redis probe writes. Проверки переданы отдельной Luna: snapshot `/private/tmp/auth-project-smtp-v1.wqg_6uf0`, base07c448b, manifest3 `/private/tmp/auth-project-smtp-v1-manifest.sha256`, metadata `/private/tmp/auth-project-smtp-v1-snapshot.json`; Luna: affected race и actual full command SQL PASS без SKIP; task check повтор с доступом к loopback PASS exit0/lint0. Первый sandbox bind failure был ограничением окружения. Manifest3 совпал до/после и с main; source не менялся. Локальный verification gate этого блока закрыт. Сервер без STARTTLS проверяет безопасный отказ, не успешную внешнюю доставку.

## Следующий шаг

Продолжить selected email/outbox consumers и bounded delivery workers/provider/token assembly после фиксации проверенного SMTP-блока. Не публиковать availableMethods/readiness до prerequisites. MP5 routing, MP6R security/refactor, MP7/MP8 и согласование UI остаются дальше. UI не начинать.

## Процесс и ограничения

- Локальный исследователь Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889, переиспользуется; прочитал только targeted SMTP/fixtures карту, tests не запускает. Не закрывать после каждого отчёта. Bohr закрыт по запросу пользователя.
- Все executable checks/tests/fixtures — «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на explicit snapshot/cwd; default worktree6377/auth stale. Здесь только форматирование/diff/snapshot, не ждать весь прогон. [Процесс](development-workflow.md).
- UsePool callback не сохраняет pool/service/async работу и не вкладывает registry acquisitions. Shared dependencies не закрывать. Current-key guard не обещает распределённую мгновенную отмену SMTP side effect после финальной проверки.
- PostgreSQL + обязательный Redis без fallback. Новые зависимости — только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Коммит только по запросу.
- Предыдущие password/MFA blocks проверены и закоммичены:186adf5/cae37b9; процесс07c448b. MFA evidence — в history. Их PASS не подтверждает текущий SMTP diff.
