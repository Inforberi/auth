# Внешний вход в независимый проект

MP4.1j, 25 октября 2026. Реализация и локальные проверки Luna завершены успешно.

- Подключить существующий OIDC browser flow для фиксированных Google и Telegram: start/callback, привязка и отключение внешнего аккаунта. Произвольные issuers, новый OAuth server и SSO не добавляются.
- Сохранённые credentials и их версия читаются из выбранной проектной БД без ENV seed/fallback. Callback и лимиты задаются доверенной конфигурацией. SQL policy остаётся authority для включения метода и регистрации.
- Два общих владельца HTTP/JWKS на процесс. Для операции создаётся только immutable client view с project Client ID/Secret/redirect; кеш ключей не умножается по проектам. Закрывает владельца процесс после drain, компонент проекта только заимствует.
- Redis state/cipher/лимиты разделяются project scope и методом, сохраняются browser binding/PKCE/nonce/single-use/provider revision. Смешение callback одного проекта с flow другого отклоняется до provider network. Callback URI и внешние cookies/routes остаются задачей MP5, этот блок их не публикует.
- Один logical UsePool на операцию, current key до/после; pool/service не выходит за callback. Во время provider network не удерживать physical SQL connection. Существующие SQL identity/session/version/MFA гарантии не копировать и не ослаблять.
- MFA использует общий coordinator и принимает только выбранный фиксированный issuer. Recovery при потере всех факторов остаётся закрыт.
- Проверки: main formatter/diff; отдельная Luna task check, affected race, локальные provider integration fixtures и actual SQL/Redis start/callback/replay/rotation/policy/isolation. Реальные внешние credentials отсутствуют, внешний login не объявлять проверенным. Новых зависимостей/таблиц/ENV/public readiness нет.

## Реализованный контракт

`NewProjectOIDC` принимает trusted runtime key, `ProjectOIDCConfig` и общие registry/reader/Redis/`ProjectOIDCClients`. `Provider` допускает только `google` или `telegram`. Отключённый компонент не требует зависимостей. Включённый проверяет прежними validators HTTPS callback с точным путём провайдера, положительные per-minute budgets, timeout и session/MFA config. Host callback задаёт доверенная сборка приложения; HTTP Host/user input не может выбирать эту конфигурацию. Проверка соответствия project origin, внешняя маршрутизация и cookie matrix остаются MP5.

- `Start` возвращает provider URL и browser binding. Код/nonce/PKCE/state ведёт существующий flow.
- `Callback` возвращает общую browser session либо MFA challenge; для link — прежний результат `Linked`. Provider revision проверяется до exchange и в финальных SQL identity/session/MFA transactions.
- `StartLink`/`Unlink` используют существующие проверки project session/fresh-auth и запрет потерять допустимый способ входа. Platform operator proof не подставляется вместо project session.
- `CompleteMFA`/`StartMFAEnrollment`/`ConfirmMFAEnrollment` используют тот же private coordinator, что password/email OTP, с точной проверкой выбранного issuer.

`NewProjectOIDCClients` создаёт владельцев для двух фиксированных провайдеров без сетевого подключения и без credentials. Операционный view заимствует transport/JWKS, получает текущие credentials и immutable redirect; shared owner не изменяется. Владелец процесса обязан вызвать `Close` после завершения операций; компонент проекта его не закрывает. Автоматическое lifecycle/HTTP подключение этим внутренним API не добавляется.

Проектная сборка не инициализирует provider settings из ENV. Отсутствующая строка, неготовые credentials, ошибка decrypt/SQL/Redis дают отказ. Регистрацией управляет текущая сохранённая SQL policy, а не отдельная копия флага в конфигурации сборки. Собственный `CheckPolicy` caller передать не может.

## Проверки и ограничения

Добавлены unit disabled/config/issuer-bound MFA, параллельные immutable credentials+redirect views и actual project SQL/Redis fixture для обоих провайдеров: сохранённый Client ID/callback/PKCE/nonce, неверный binding, state другого метода, чужой project scope, rotation до exchange, replay, перечитывание нового Client ID, отключённая policy и отсутствие выданных сессий. Чужой scope в fixture — негативная проверка Redis, не приёмка двух полноценных deployment/БД.

Main: formatter и diff review; targeted review Helmholtz без найденных конкретных ошибок. Проверки Luna PASS: task check exit0/lint0, affected race exit0, локальный TLS OIDC-клиент и полный command SQL+Redis exit0 без SKIP. Первоначальный sandbox не разрешил loopback bind; тот же race suite успешно прошёл с доступом к loopback. Manifest10 совпал до/после и с рабочим кодом; RedisDB15 пуста, собственные PostgreSQL/Redis containers удалены. Реальные внешние login/link/MFA и общая MP5/MP7 browser/fleet приёмка NOT RUN. Ни успешный Start, ни локальные тесты не доказывают принятие credentials внешним провайдером.

31 октября принят TestTwoProjectOIDCIsolationSQL: actual TLS/HTTP start/callback Google и Telegram в A/B над отдельными БД, свои credentials/callback URI, scoped Redis flow/binding, подписанные RS256 ID tokens с nonce/audience/issuer и S256 code exchange. Проверяются чужой проект/провайдер/cookie/code, replay, неверный nonce/PKCE, повторный login без слияния по email/между issuers, независимые provider revisions и отсутствие fallback credentials. Luna V1 task check и V4 targeted lint/actual OIDC root race/count1 PASS, cleanup/manifest10 подтверждены; [scope и условия отдельного контейнера](../planning/multi-project.md#oidc-callbacks-двух-проектов--mp5-oidc-http). Production-клиент и его TLS/endpoint guards прежние, настоящий внешний provider/browser/linking sign-off остаётся отдельно.
