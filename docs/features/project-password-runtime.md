# Первая проектная Auth-сборка: пароль и SQL-сессия

MP4.1b, 25 октября2026. Решение зафиксировано перед реализацией; реализация и локальные проверки Luna PASS.

- Практический первый потребитель MP4.1a — внутренний `ProjectPassword.Login`, использующий существующие PasswordService и SessionService. Входной trusted runtime Key задаёт конкретный проект; ключ шифрования/policy читаются loader при создании объекта, Redis scope — project UUID. Сессия сохраняется в той же проектной БД.
- `Registry.UsePool` удерживает lease всего pool entry без захвата физического соединения. Callback получает существующий borrowed `*pgxpool.Pool`; не вправе Close/сохранить pool, сервисы или async работу за пределами callback. Запрос собирает дешёвые существующие repo/service objects и завершает их операции внутри callback. Хеширование не занимает SQL connection/transaction. Второго pool и кеша realms нет.
- UsePool удерживает слот MaxAcquiring до выхода callback: ограничены не только cold opens, но и число таких логических операций; при saturation fail-fast. Это shared budget с короткими SQL acquisitions; не вкладывать Registry.Use/UsePool из callback. Настройки лимита не являются заявленной capacity.
- Bounded hasher, Redis client и reader заимствуются у процесса; не создаются и не закрываются на проект/запрос. Single-flight open, entry cap, idle retirement и drain/Close остаются у registry; инвалидированный pool закрывается после последнего lease.
- До логина и перед выдачей результата проверяются current catalog key/reader profile. Suspend/rebind/смена epoch отбрасывает raw-token result. Already committed session при таком отказе не превращается в массовый revoke; raw token не выдаётся. Эта проверка не обещает остановить in-flight действия одновременно с catalog commit.
- Early CheckPublic до hash и final locked SQL policy/auth_version/email verification/MFA-role guards при session INSERT сохраняются; их не заменяет cold snapshot. При enrolled или обязательной role MFA этот первый Login отказывает до подключения полного MFA challenge flow. Нельзя объявлять его MFA-ready.
- Операционные TTL/capacity/timeout передаёт trusted assembly, не пользовательский запрос. Общий session config validator переиспользуется без дублирования правил. Credentials/доставка/OAuth/JWT/registration/recovery не seed-ятся из ENV этим API.
- Нового HTTP route/host routing/setup/public-ready/capabilities нет. До их публикации нужны полный MFA/selected method dependencies, readiness и MP5 guards. UI не начинается.

Проверки: lease/single-flight/retirement/shutdown/bounded concurrency без SQL connection capture; unit config guards; actual project SQL+Redis password/session pipeline, wrong password/blocked/disabled/unverified/MFA/suspend, no extra pools, no-init/no public routes. Выполняет Luna на frozen snapshot; тестовые пользователи/ролей/настроек только в disposable fixture, исходные данные соседних drills восстанавливаются.

## Реализованный внутренний API

`NewProjectPassword(ctx,key,cfg,deps)` загружает проектный data key через MP4.1a loader и создаёт scoped limiter; сохраняет только immutable key/config и borrowed dependencies. Не вызывает Config.Load, policy.Initialize, provider/SMTP setup или создание hasher/SQL pool.

`Login(ctx,input)` ограничен cfg.Timeout (положительный, ≤30s); native hash не прерывается посередине, действуют существующие bounded hasher/context checks. Registry.UsePool держит логический lease и MaxAcquiring slot до завершения callback. Внутри создаются дешёвые request-scoped repo/service objects на original pool; после SQL-session commit повторяется catalog/profile guard. При любом отказе результат/raw token не возвращается. Pool всегда закрывает registry после drain; API не имеет Close для borrowed process dependencies.

Session TTL/capacity берутся из trusted cfg; правила session durations перенесены в `sessionservice.Config.Validate`, прежний config validator делегирует им, сообщения/границы не изменены. Это не per-project UI settings API для TTL.

SMTP/OAuth/JWT/recovery/registration и полный MFA не реализованы этим блоком. При необходимости MFA SQL отказывает до выдачи сессии. Current platform availableMethods остаются false: наличие internal Login не разрешает host routing/readiness или публичный endpoint. Повторная сборка на новой epoch — обязанность следующего runtime manager, старый объект не переключает проект самостоятельно.

Функциональный SQL+Redis drill добавлен в существующий full command fixture: реальный Argon2/hash, session в project DB, wrong password/disabled/unverified/blocked/MFA guards, live SQL query во время остановленного hash с poolMaxConns1, suspend во время hash с отказом выдачи raw token. RedisDB15/loopback и `AUTH_PROJECT_PASSWORD_TEST_REDIS_ADDR/PASSWORD` — только synthetic test fixture, не operational ENV. Cleanup удаляет только заранее известные scoped keys/собственного пользователя/роль и восстанавливает policy.

## Результат проверок

Luna: task check PASS/lint0, affected host race PASS, полный actual TestPrepareCommandSQL PASS без SKIP, включая восемь project_password_session cases и прежние loader/runtime/roles/onboarding/managed/parent replay checks. Manifest9 совпал до/после и перед коммитом. Owned PostgreSQL/Redis удалены, DB15 пуста. [Evidence](../planning/history.md#результат-mp41b-project-password-session--25-октября-2026). Это локальная приёмка внутреннего Login, не публикация HTTP/MFA challenge/full Auth readiness/fleet.
