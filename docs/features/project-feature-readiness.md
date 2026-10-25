# Готовность выбранных функций проекта

MP5.1a, 25 октября 2026. Реализован внутренний builder; локальные проверки Luna PASS.

- Сборка читает current exact origin/key и SQL policy snapshot, строит только выбранные deployment/public функции существующими конструкторами и повторно проверяет key/policy version в конце. Изменение во время сборки закрывает результат, не включает routes частично по старому snapshot.
- Browser profile выбирается явно, native/JWT — своим существующим config. Это выбор режима deployment, не caller-supplied readiness booleans. Закрытый профиль и password с disabled verification не требуют SMTP. Email OTP/selected verification/recovery требуют сохранённый project SMTP и реальный запущенный shared delivery scheduler с теми же registry/reader/Redis/allowlist.
- У каждого выбранного feature — ready или безопасная причина unavailable; raw errors/secrets не включать в отчёт. Неготовый feature не попадает в route plan; независимые ready features остаются в плане. Existing domain/config validators не дублировать.
- Provider constructors дополнить reusable stored-credentials check: одной успешной сборки OIDC недостаточно. Exact callback/verification origin и JWT issuer должны принадлежать выбранному origin. Это локальная configuration readiness, не подтверждение внешнего Google/Telegram/SMTP.
- Browser session/MFA config должен быть согласован между выбранными ready methods. Shared MFA completion принимает только успешно собранные primary methods и тот же scope. Recovery при потере всех факторов по-прежнему закрыт.
- Результат хранит actual pool-free components и immutable route plan с явным transport profile, а не фиктивные availableMethods. Builder не вызывается на каждый пользовательский запрос. Source/profile version проверяется отдельно; нет positive authority cache, новых pools/worker/schema/ENV/deps.
- Не регистрировать routes и не переводить phase в ready. HTTP profile mounting/management sessions/CORS/cookies/callback acceptance/lifecycle остаются следующим блоком; user/admin authorization никогда не следует из route plan. UI не начинать.
- Main formatter/diff, Luna task check/affected race/security и actual SQL+Redis закрытый/password-noSMTP/provider-only/missing-mail/stored-credentials/origin/issuer/policy revision/route-plan случаи.

## Контракт сборки

`BuildProjectProfile` получает доверенные key/origin и bounded config, читает актуальную SQL policy и строит существующие компоненты. `BrowserEnabled` выбирает browser deployment; SQL-флаги определяют доступные методы. Native/JWT выбираются отдельно. Выключенный профиль не требует Redis/SMTP/hasher; verification-only не требует hasher. Обычные пользовательские запросы не должны повторять эту сборку.

`Readiness()` возвращает копию отсортированного отчёта: origin, policy version, observedAt, общий Ready и состояния выбранных функций. Непостроенный профиль не считается готовым. Причины ограничены безопасными кодами (`missing_configuration`, `redis_unavailable`, `delivery_not_running`, `provider_credentials_unavailable`, `origin_mismatch` и др.), без сырых ошибок/секретов. Общий Ready=false не скрывает независимые готовые методы из `RoutePlan()`.

Verification и recovery выбираются отдельно. Нужны сохранённые SMTP settings, действующий delivery runner с теми же registry/reader/Redis и его фактический allowlist. Проверка отражает локальную готовность конфигурации и процесса, а не успешную отправку письма. Конфигурация verification в корневом профиле является единственным источником для регистрации; standalone `Password.RegistrationVerification` заменяется ею. Email reauthentication может работать самостоятельно при выключенном основном OTP-входе.

Google/Telegram требуют сохранённых credentials и callback строго `origin + /api/v1/auth/{provider}/callback`. Успешный внешний вход не заявляется без реальных provider secrets и отдельной проверки. JWT issuer равен выбранному origin. JWT-only использует отдельный issuance Redis и не требует обычного Redis, SMTP или hasher. Native password/email пересекаются с SQL-политикой и operational flags; refresh требует включённой SQL native policy, logout сохраняется для существующих refresh-сессий при наличии настроенного native-компонента.

Готовые browser-методы должны использовать одинаковую session/MFA policy. При несовпадении они исключаются из плана; независимый email reauthentication сохраняется. Общий MFA coordinator принимает только готовые primary methods. Recovery при потере всех факторов не открывается этим блоком.

`CheckCurrent` повторно разрешает origin/key, сравнивает полный SQL policy snapshot и проверяет актуальность runtime. При конфликте вызывающий код отбрасывает профиль и собирает новый. Это проверка на момент обращения, не блокировка будущего изменения и не автоматическая инвалидация кеша. Сервисы и пулы не сохраняются из lease callback; владельцы shared resources остаются прежними.

## План маршрутов и границы

`RoutePlan()` возвращает новую копию metadata для готовых функций: feature, method, path, protection. Protection обозначает требуемый профиль будущего HTTP-mounting: browser, callback, public_keys, native, service либо session_no_refresh. Последний нужен для reauthentication/exchange с действующей сессией без её продления. Эти строки не заменяют middleware или проверку полномочий. OPTIONS также требует соответствующего существующего transport protector.

Маршруты ещё не подключены к серверу. Resident handler cache/lifecycle, account/session/MFA management profiles, настройки capabilities и phase-ready publication остаются следующим блоком. Полная cookies/CORS/CSRF/callback/redirect matrix и cross-project acceptance открыты. Cross-origin браузерный доступ этим изменением не включён. UI не начинается.

## Проверки

Добавлены unit-проверки независимых методов, immutable copies, закрытого профиля, выбора Redis и согласованности browser policy. В существующий actual `TestPrepareCommandSQL` добавлены closed/password-noSMTP/missing-verification/stored-provider/callback/issuer/policy-conflict сценарии, verification без hasher, реальный delivery start/stop и reauth-only. Fixture восстанавливает свои SQL settings/provider rows, останавливает свой runner и не отправляет внешнюю почту.

Main: formatter и diff/source review. Luna: task check, affected race, security и полный actual command SQL/Redis/TLS/SCRAM прогон на immutable snapshot. Luna: task check (lint 0 issues), affected race, security и полный Linux ARM64 TestPrepareCommandSQL PASS, exit 0. Вложенный selected_feature_readiness прошёл, SKIP нет. Manifest всех 15 source files совпал после проверок и с main. Отдельный TestPostgresSchema не запускался: schema не менялась. Сканер не нашёл вызываемых кодом уязвимостей; одна отмечена в модуле без вызова из проекта. Собственные стенд и временные credentials/binary удалены. Внешний provider/SMTP прогон остаётся ограничением.
