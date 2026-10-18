# Локальный HTTPS-стенд

J7.3-local, 17 октября 2026. Это постоянный **локальный synthetic sandbox**, не production и не эквивалент внешней/fleet/load приёмки. Реальные `.env`, `.env.prod`, SMTP/provider secrets и рабочая `auth-db` не используются.

## Запуск и адреса

```bash
task sandbox:up
task sandbox:down
```

Up создаёт сертификат, запускает отдельные PostgreSQL/Redis/Mailpit, применяет initial schema к своей БД, выдаёт restricted runtime grants и собирает текущий Auth через production Dockerfile. В конце ждёт HTTPS readiness с ограниченными retries и проверкой CA. Down останавливает только Compose project `auth-sandbox`, **сохраняя** его named volumes и тестовые данные; volumes автоматически не удаляются.

| Назначение | Адрес/доступ |
| --- | --- |
| Auth API | `https://localhost:18443/api/v1` |
| Swagger | `https://localhost:18443/swagger/index.html`, Basic `sandbox` / `sandbox-swagger-only` |
| Liveness/readiness | `https://localhost:18443/health/live`, `/health/ready` |
| Mailpit, только захваченная локальная почта | `http://localhost:18026` |

Порты привязаны к127.0.0.1; PostgreSQL/Redis/SMTP наружу не опубликованы. Не делать SSH tunnel/public port forwarding этого профиля. Network/volumes имеют префикс `auth-sandbox`, отдельные от dev/prod; не добавлять external volumes. Profile использует только `.env.example` и явные synthetic overrides, а не `DEV_ENV`/`PROD_ENV`. Повторный up сохраняет пользователей и не открывает повторно завершённый initial setup.

## TLS

Локальный self-signed сертификат на30 дней с SAN localhost/127.0.0.1: `tmp/sandbox/tls.crt`, private key `tls.key`. Каталог700, ключ600; API запускается non-root с UID/GID текущего пользователя для чтения readonly bind, root filesystem readonly/capabilities dropped. Не переносить профиль/ключи в production. Системное хранилище доверия не меняется автоматически; браузер может показать предупреждение. Для CLI:

```bash
curl --cacert tmp/sandbox/tls.crt https://localhost:18443/health/ready
```

Не использовать `-k` как результат проверки TLS. Expired/mismatched certificate требует перевыпуска и повторного доверия локальному certificate; наличие файлов не считается автоматическим renewal. Не перезаписывать их во время активного TLS drill.

## Подготовленные пользователи

Эти публичные тестовые пароли допустимы **только** в этом изолированном sandbox. Не использовать реальные учётные данные/данные клиентов и не повторять эти credentials в других проектах.

| Пользователь | Пароль | Состояние |
| --- | --- | --- |
| `ivan@sandbox.example` | `Sandbox-Ivan-2026!` | Обычный пользователь, email подтверждён; password и email OTP работают |
| `petr@sandbox.example` | `Sandbox-Petr-2026!` | Обычный пользователь; созданная при проверке сессия отозвана, можно войти заново |
| `admin@sandbox.example` | `Sandbox-Admin-2026!` | System super_admin, verified email, enrolled TOTP; парольный вход требует MFA |

Пользователи созданы через реальные HTTPS register/setup endpoints, не SQL fixtures и не seed на каждом запуске. После добровольного удаления sandbox volumes up создаст пустую БД: таблица выше не означает auto-provisioning. Пользователей можно снова зарегистрировать через Swagger/API. Для нового super-admin действуют штатные setup/start → код из Mailpit + TOTP → setup/complete; synthetic X-Setup-Token задан в `deploy/compose.sandbox.yml`, только до durable initialized marker.

Локальные ответы setup/TOTP URI находятся в `tmp/sandbox/admin-setup.json`, набор recovery codes — в `admin-recovery.json`. Это чувствительные **тестовые** артефакты в игнорируемом каталоге, файлы600; не коммитить/не пересылать их. Код с индексом0 уже использован для MFA-входа при проверке. Остальные setup/JSON/cookie jars там же — не production secrets и не механизм хранения credentials для будущего UI. Можно добавить setup URI/secret в тестовый authenticator; не вставлять его в реальный аккаунт.

Mailpit хранит verification/setup/OTP письма, но не пересылает их во внешние ящики. Verification link ведёт на будущий frontend `/verify-email` (UI ещё нет); подтвердить нужно POST `/api/v1/auth/email/verify` с token через Swagger/API, не простым открытием GET-ссылки.

## Включённые профили и ограничения

Базовый `sandbox:up` включает password, email OTP, MFA и одноразовую initial setup, без JWT/native. `sandbox:jwt` ниже добавляет JWT/native с отдельными prerequisites и проверками. Google/Telegram, email binding/change и operator MFA recovery на этом стенде не включались. Invitations/temporary password включаются только на время `sandbox:admin`, после него снова выключены.

Не приравнивать Mailpit к внешнему SMTP, прямой TLS Auth к реальному ingress, программную генерацию TOTP к человеческому authenticator drill, один Auth instance к fleet. Browser/CORS/Swagger interaction реальным браузером, provider callbacks, key rotation/compromise, mixed/hostile/soak/GC/shutdown и capacity остаются открытыми.

## Что уже проверено

- Текущий binary собран, restricted runtime database login, настоящие PostgreSQL/Redis/Mailpit, прямой TLS с `--cacert` без `-k`; Swagger Basic200, readiness200.
- Регистрация двух users201, cookie `/me`200; first admin setup202 → письмо Mailpit → TOTP complete200 → password login202 → recovery-factor MFA200. Администратор читает settings200, ordinary user получает403.
- Hostile Origin не выполняет logout403; штатный logout204 делает старую cookie непригодной (`/me`401).
- Verification POST200, последующий email OTP request202 → письмо Mailpit → confirm200 → обычная SQL cookie-session `/me`200.
- При реальном stop только sandbox Redis: readiness503, liveness200, password login503. После restart Redis readiness200 без restart API. Это не latency/recovery-time benchmark; первый recovery probe ещё вернул503, поздний повтор подтвердил восстановление. Никакого fallback к SQL вместо limiter не добавлено.
- Compose config проверен на project namespace/loopback ports/no DB/Redis publication/readonly API/isolated volume names. `task check`/lint0 и vulnerability scan выполнены; details — [history](../planning/history.md#результат-j73-local--17-октября-2026).

Стенд оставлен работающим для следующих шагов. Управляемые faults проводить только по точным sandbox container names и восстанавливать зависимости; не применять эти команды к рабочему проекту. Не запускать production restore/secret rotation ради локальной проверки.

## JWT-профили — J7.4-local

```bash
task sandbox:jwt
```

Запускать после `sandbox:up` и создания трёх тестовых accounts выше. Нужен сохранённый synthetic `tmp/sandbox/admin-setup.json`: программный TOTP для отдельного administrative login. Это не команда настройки production и не обход MFA. Обычный `go test ./...` пропускает подготовку ключей и live acceptance.

Команда создаёт в ignored `tmp/sandbox/jwt` отдельный от TLS ES256 PKCS#8 key/public JWKS, resource manifest и service-secret/hash manifest; каталог700/файлы600. Полный существующий bundle переиспользуется, частичный не перезаписывается. Ни private key, ни raw secret/token/коды не печатаются и не коммитятся. Изменение готовых ключей/manifest требует отдельного controlled restart, это не автоматическая ротация.

`deploy/sandbox/access-catalog.json` подключён ко всем вариантам sandbox. Owner fixture `deploy/sandbox/jwt-fixture.sql` в одной Access-locked транзакции создаёт **только тестовую** роль `sandbox_reader` с `sandbox.records.read` и назначает существующему Ивану. Первое назначение увеличивает auth/access versions и делает старые сессии Ивана неактуальными; повтор ничего не меняет. Это explicit SQL test seed, не проверка административного API назначения и не скрипт для рабочих пользователей. Права администратора/аккаунты/password/TOTP не сбрасываются. `sandbox.records.write` объявлен, но Ивану не выдан.

JWT override включает только sandbox API: issuer `https://localhost:18443`, kid `sandbox-1`, access TTL1m. Native budget P60/min, retention B200/I1m: `2×60×65s ≤ 200×60s`. Это допустимая startup-арифметика для малой тестовой нагрузки, **не** измеренная скорость очистки или production tuning. Defaults `.env.example/.env.prod.example` не меняются.

Ресурсы:

| Audience | Режим | Permissions |
| --- | --- | --- |
| `sandbox-strict` | strict / online authority | sandbox.records.read, sandbox.records.write, accounts.users.read |
| `sandbox-local` | local / срок токена | sandbox.records.read |

Service client `sandbox-consumer` имеет только strict audience. Его raw secret хранится в `tmp/sandbox/jwt/consumer-secret`, Auth получает SHA-256 verifier, не raw credential. В API монтируются отдельные необходимые readonly-файлы: TLS cert/key и JWT key/JWKS/resources/client manifest, не весь `tmp/sandbox` с admin TOTP, cookie jars и raw consumer secret. Existing saved policy включается через HTTPS admin settings с fresh password/MFA, а не SQL UPDATE или ENV-подменой.

Live тесты в `deploy/sandbox/*_test.go` используют текущий production binary и настоящий TLS/SQL/Redis. Consumer запускается как `net/http` middleware в тестовом handler, но JWKS/introspection обращаются по сети к работающему Auth; отдельный внешний data-backend listener/ingress этим не проверен. Fault cases останавливают только Redis/PostgreSQL с точными именами **и** проверкой Compose label `auth-sandbox`, затем восстанавливают их в cleanup. Readiness ждут с учётом существующего кеша1s. Нужен доступ к Docker; тест не предназначен для одновременного запуска несколькими операторами.

После успешной проверки оба issuance switch оставляются включёнными для дальнейшей работы; данные сохраняются. Повторный `sandbox:up` запускает базовый профиль без JWT override: deployment capability выключится, сохранённая policy не перезапишется. Для повторного включения/проверки — `sandbox:jwt`; `sandbox:down` сохраняет volumes и для JWT-варианта.

Результаты и границы приёмки — [матрица J7](jwt-security-acceptance.md) и [history J7.4](../planning/history.md#результат-j74-local--17-октября-2026). Fleet/rotation/ingress/browser/нагрузка/GC и внешние интеграции остаются отдельными gates.

## Пользователи и роли — pre-ui-admin-local

```sh
task sandbox:admin
```

Нужны работающий JWT sandbox, подготовленный администратор/TOTP и Mailpit из профиля выше. Команда явно включает `AUTH_SANDBOX_ADMIN=1` и запускает `TestAdminAcceptance` с `-race`; обычный `go test` пропускает live-тест. Race detector относится к тестовому клиенту/SDK, не к отдельно работающему production API.

Тест временно пересоздаёт только sandbox API с invitations/temporary-password и локальным invitation URL. Отдельный override хранится в новом ignored каталоге `tmp/sandbox/admin-*`; исходные ENV, ключи, policy и volumes не переписываются. Через API создаются два новых пользователя с уникальными адресами и custom role. Активация использует письмо из локального Mailpit, не внешний SMTP. Пароли/коды/токены не печатаются. Разрешения роли — уже доступные администратору `accounts.users.read/manage`, без bootstrap внешних permissions или SQL-назначений.

Проверяются одноразовость activation/temporary secret, обязательная смена временного пароля без выдачи session, отсутствие автоматического email verification, directory/cursor, grant/no-op/edit/revoke, version conflicts, block/unblock и last-admin guards. Расширение роли инвалидирует прежний снимок сессии, сокращение сохраняет вход, но сразу убирает права; strict JWT проверяется через настоящий consumer. После unblock отдельно повторяются сохранённая старая cookie и старый JWT: они не оживают. Незавершённый MFA и обычный public admin login не заменяют private fresh admin proof.

Cleanup снимает назначение созданной роли и возвращает исходный JWT deployment. Новые accounts остаются active без ролей, созданная роль — без назначения: их можно посмотреть позже в UI. Повторные запуски создают новые синтетические записи; это не тест retention/capacity. Если runner принудительно завершён, cleanup не гарантирован: остановить runner, вернуть deployment через `task sandbox:jwt`, проверить созданные IDs и снять только их тестовые назначения через API. Не сбрасывать БД/Redis и не удалять весь `tmp/sandbox`.

NOT RUN этим блоком: actual delete обычного пользователя, invitation/temporary reissue, истечение fresh proof по времени, role-required MFA enrollment, выдача special super-admin, browser/external SMTP, fleet/load/GC. Локальный PASS не закрывает весь pre-ui gate.

## Ротация и недоступность JWKS — J7.5-local

```bash
task sandbox:jwt:rotation
```

Нужен уже работающий JWT sandbox с исходным kid `sandbox-1`, существующим Иваном и включённым session exchange. Команда кратковременно останавливает **только API auth-sandbox**; не запускать параллельно другим тестам/ручной работе со стендом. Рабочие проекты не затрагиваются, SQL/Redis/Mailpit не перезапускаются, существующие users/roles/policy и исходные файлы `tmp/sandbox/jwt` не переписываются. Обычные login/exchange создают тестовые session/audit записи и учитываются действующими Redis-лимитами.

В новом ignored временном подкаталоге создаются отдельные synthetic private keys A/B и phase manifests. Исходный sandbox-1 остаётся в verification set во всех фазах. Только временный override меняет signer/JWKS и access TTL3m: срок заведомо больше60s доверия к кешу, чтобы отказ нельзя было объяснить обычным expiry. File mounts readonly, алгоритм/таймеры/admission/retry SDK прежние; новых runtime API/worker/dependency нет.

Порядок проверки:

1. Подписать A и проверить strict/local через настоящие Auth/JWKS/introspection/SQL.
2. Опубликовать B, дождаться обычного refresh consumers, затем переключить signer на B: старые и новые токены работают в overlap.
3. Досрочно удалить A из authoritative trust и обновить consumers: ещё не истёкшие A-токены отклоняются, B продолжает работать. Это **отдельная симуляция emergency distrust**, не разрешение удалять planned key до истечения TTL+skew. Полный planned TTL-drain/fleet rollout этим не проверен.
4. Создать fresh consumer owners и остановить actual sandbox API. Strict даёт503 из-за недоступной online authority; local временно даёт204 с ещё свежим trust. После заведомо неудачного JWKS fetch и истечения исходных60s `Ready`/middleware закрываются с503 при всё ещё действующем JWT.
5. Запустить API с B и после обычного fetch backoff проверить те же credentials: B снова204 без нового login; A остаётся401.
6. Cleanup возвращает исходный Compose JWT profile/kid sandbox-1/TTL1m и public set, затем удаляет **только созданный временный подкаталог** с A/B. Исходные private/public manifests не переписываются. При ошибке восстановления артефакты сохраняются для диагностики; не удалять их до восстановления baseline.

Нет TLS proxy или поддельного JWKS server: fetch идёт на actual Auth HTTPS endpoint с CA verification. Поэтому fault означает **весь Auth недоступен**, а не отдельную JWKS-only partition при доступной introspection. Strict stale-trust отдельно наблюдается через публичный `Ready`, не выдаётся за избирательный сетевой эксперимент. Положительные authority decisions не кешируются и strict не переключается в local.

Это single-instance приёмка SDK/deployment механики. Реальный compromise, emergency traffic fencing/operator/fleet, различающиеся JWKS узлы, selective network partitions, нормальное planned TTL-drain, browser/ingress и нагрузка/GC остаются отдельными gates. Возврат исходного **не скомпрометированного** test key — cleanup теста, а не рекомендация возвращать compromised keys в production trust.

При принудительном завершении runner (например, SIGKILL/жёсткий test timeout) cleanup не гарантирован. После остановки runner вернуть штатный профиль и проверить его можно `task sandbox:jwt`; до успешного возврата baseline не удалять временный подкаталог, который ещё может быть смонтирован API. Оставшиеся артефакты такого прерванного прогона проверяются отдельно, без удаления всего `tmp/sandbox/jwt`.
