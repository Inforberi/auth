# Проверка проектного JWT внешними сервисами

MP4.1l, 25 октября 2026. Реализация и локальные проверки Luna V2 завершены успешно.

- Переиспользовать existing Introspection и consumer SDK. Проектные issuer/resources/public keys берутся из того же ProjectTokens, что выдаёт JWT; непроверенный token не выбирает ключ/проект/URL.
- Добавить optional доверенный manifest клиентов к project config, без ENV/file/global fallback или нового SQL. У каждого проекта свой набор ID/hash/audiences; разрешённая ротация — прежние два verifiers. Raw secret в Auth config не хранить и наружу не возвращать. Совпадение client ID не делает credentials глобальными; повторное использование одного секрета в нескольких доверенных manifests — явное расширение полномочий оператором, не автоматическая изоляция от ошибки конфигурации.
- Resident IntrospectionFactory владеет immutable parsed clients/resources/verifier и общим admission32; request-local Bind добавляет только repository под одним UsePool, без pool escape. Использовать прежний scoped limiter/shared no-retry Redis owner, не новый pool/worker.
- Сохранить существующий Authenticate/Inspect контракт для будущего HTTP adapter. Unknown credentials не открывают SQL; окончательное разрешение только после current runtime guards и online SQL authority. Успешная проверка credentials сама по себе не означает доступность проекта.
- Проверять полный signed token; scope только сужается до актуальных прав. Block/revoke/role revision/API-family/expiry остаются SQL authority. Нет positive auth cache, sliding UPDATE и per-invalid-token audit writes. Ошибки SQL/Redis fail closed, чужой token — inactive без metadata.
- Внешний backend использует existing pkg/authjwt.Consumer с фиксированными trusted issuer/JWKS/introspection URLs и собственным raw credential. Не создавать consumer внутри Auth для сетевого запроса к самому себе. Public HTTP host/issuer/cookie/MP5 matrix и fleet rotation/readiness этим блоком не открываются.
- Main formatter/diff; Luna task check/affected race и actual project SQL+Redis valid/inactive/foreign key+issuer+client/audience/block/revoke cases, existing consumer/TLS/SQL regressions. Новых dependencies/schema/ENV/public routes/UI нет.

## Реализация

`ProjectTokenConfig.Introspection` — optional `ProjectIntrospectionConfig` с client manifests и consumer/project per-minute budgets. Issuer/resources/public key отдельно передать нельзя: сборка получает их из того же immutable token config и prepared signer. При отсутствии настройки JWT работает без introspection. Выключенный JWT не загружает проектные зависимости ради этой опции.

`IntrospectionFactory` создаётся один раз на resident token component. Parsed clients/resources, issuer verifier, admission32 и scalar budgets общие между привязками; исходные client/resource slices после сборки не удерживаются. `Bind` получает SQL repository только на время запроса. Existing standalone `NewIntrospection` переиспользует ту же factory, сохраняя свой API и проверки.

`ProjectTokens` реализует существующий HTTP-facing интерфейс `Authenticate`/`Inspect`:

- `Authenticate` проверяет только свой immutable manifest, без SQL и без передачи usable secret в конфигурацию. Отсутствующая introspection безопасно возвращает false. Это не readiness и не разрешение доступа к данным.
- `Inspect` работает под existing `UsePool`/current-key guards, получает request-local repository и вызывает прежнюю crypto + SQL authority. Client proof другого factory не принимается даже при совпавшем ID. Ошибки не возвращают active/metadata; final stale guard также очищает результат.
- Допустимый JWT проверяется по текущей project SQL authority, inactive/invalid — только inactive. Допустимая подпись не отменяет consumer audience allowlist, block/revoke/MFA/role checks. Решения не кешируются и не обновляют TTL сессии.

Redis prefix `jwt-introspection` и HMAC остаются project-scoped, client/project counters имеют прежний TTL; используется тот же no-retry owner, что issuance. Сессии, audit, SQL schema и underlying authority transaction не изменены.

## Внешний backend

Существующий `pkg/authjwt.Consumer` запускается во внешнем сервисе с фиксированными `Expected{Issuer,Audience,Mode:strict}`, `JWKSURL`, `IntrospectionURL`, `ClientID`, `ClientSecret`. Secret передаётся через защищённый runtime secret mount/manager, в Auth — только SHA-256 verifier. Сервис не выводит endpoints из claims и не подставляет secret пользователя/оператора. Lifecycle `Ready`/`Close`, bounded TLS transport, no redirects/retries и maximum trust age сохраняются по [контракту SDK](jwt-consumer.md).

Отдельного SDK/consumer внутри Auth нет. Эта сборка предоставляет compatibility с существующим HTTP adapter, но не регистрирует маршруты и не загружает глобальный manifest. Проектные public URLs, UI управления clients и fleet rotation должны получить отдельный доверенный source/admission; этот блок их не имитирует.

## Проверки

Добавлены unit shared admission/репозиториев/client proof ownership, disabled/optional introspection и compile-time совместимость с HTTP interface. Existing actual project token fixture дополнена valid JWT/invalid JWT, forbidden audience, независимыми manifests с одинаковым client ID и разными secrets, чужим issuer, block и logout authority. Независимые manifests/issuer в fixture используют один собственный project storage для точечной отрицательной проверки; это не полная приёмка двух БД/проектов.

Локальные проверки Luna V2 PASS: task check/lint0, affected race, security (нет вызываемых кодом уязвимостей; одна в dependency недостижима по scanner), Linux ARM64 full TestPrepareCommandSQL и TestPostgresSchema, включая introspection/consumer/token/native regressions. Manifest11 совпал до/после и с main. Свои containers/network/credentials/test binaries удалены. Public HTTP, MP5/MP7/fleet/load/GC/UI gates остаются открыты.

31 октября принят TestTwoProjectTokenIsolationSQL: два actual HTTP profiles/БД со своими issuer/keys и разными secrets при одинаковом client ID/audience, чужие credentials401, чужой JWT inactive без metadata, forbidden audience403 и независимый online revoke. Luna V1 task check/token isolation race, cleanup/manifest11 PASS; [scope](../planning/multi-project.md#jwt-и-native-двух-проектов--mp5-token-http). Ограничение same-DB fixture для этого локального HTTP scope снято фактическим PASS; browser/external consumer/fleet gates остаются отдельными.
