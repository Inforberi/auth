# Подключение проектного HTTP к приложению

MP5.1c, 25 октября 2026. Реализовано, локальные проверки Luna V1/V3 PASS.

Один существующий direct-TLS listener: exact PLATFORM_ORIGIN обслуживает operator router, остальные Host проходят project HTTP boundary и SQL catalog lookup. Unknown/foreign/plain HTTP не попадают в operator fallback. Нужен сертификат для обоих пространств доменов; реальный TLS/deployment не меняется автоматически.

PLATFORM_PROJECT_HTTP_ENABLED=false по умолчанию. Opt-in требует platform/runtime/direct TLS и ограниченные profile/build/admission budgets. Project HTTP использует отдельный bounded admission на том же listener; суммарные ceilings operator+project учитываются явно, shared SQL/Redis/hasher прежние.

Первый deployment source подключает browser password/MFA и, при включённом project delivery, verification/recovery. Только operational budgets/durations берутся из общей конфигурации; origin email links выводится из проверенного project origin, encryption keys/SMTP credentials берутся существующими project factories из project scope. Global public-method flags и provider secrets платформы не используются как настройки проектов. OIDC/OTP/native/JWT factories уже существуют, но их deployment capabilities/manifests подключаются следующим отдельным шагом, без глобального fallback.

Запуск использует прежний server и delivery lifecycle. После server drain dispatcher прекращает admission/drains до join workers и закрытия registry/private reader/shared clients. При App.Close без Run прежние LIFO owners закрывают ту же сборку. Флаг off не создаёт никаких новых owners/lookup/workers. Catalog phase-ready и полный MP5 release gate этим opt-in не меняются. UI не начинается.

Main formatter/diff/source review. Luna task check/affected race/security, actual operator/runtime assembly SQL и command TLS HTTP regression. Ни тесты без actual SQL, ни opt-in не означают полную two-project/external/fleet acceptance.

## Operational config

| ENV | Default | Назначение |
| --- | --- | --- |
| PLATFORM_PROJECT_HTTP_ENABLED | false | Подключает project handler за тем же server TLS listener |
| PLATFORM_PROJECT_HTTP_MAX_PROFILES | 8 | Resident assemblies, 1..256 |
| PLATFORM_PROJECT_HTTP_MAX_BUILDING | 2 | Одновременные cold builds, не выше MaxProfiles |
| PLATFORM_PROJECT_HTTP_BUILD_TIMEOUT | 5s | Deadline сборки, не больше общего HTTP_REQUEST_TIMEOUT |
| PLATFORM_PROJECT_HTTP_PROFILE_MAX_AGE | 30s | Пересборка локальной readiness, 1s..5m |
| PLATFORM_PROJECT_HTTP_MAX_IN_FLIGHT | 32 | Отдельный project admission, не выше половины runtime acquire slots |

При default HTTP_MAX_IN_FLIGHT=128 сумма admission ceilings — 160 на процесс; это ограничение конкурентности, не RPS. Registry/SQL budget и общий bounded hasher остаются едиными для обоих routers. Флаг off не валидирует неиспользуемые project HTTP параметры и не создаёт новый worker, listener или clients. После изменения ENV нужен restart. Real env/TLS/БД не менялись.

Source копирует operational durations/budgets один раз, возвращает отдельные config values на каждый key/origin, очищает EMAIL_OUTBOX_KEY. Project key, SMTP, account policy, roles и provider credentials остаются в соответствующих project stores. Global Google/Telegram/JWT config не включается через этот source. MFA recovery при потере всех факторов и временные пароли этим deployment-профилем не публикуются.

Server drain вызывает realm.drainHTTP перед join workers; при исходном signal context workers уже могут завершаться, это не обещание сохранить отправку во время shutdown. Долговечные outbox события остаются для следующего запуска. Dispatcher drain зарегистрирован также в idempotent LIFO resources для App.Close без Run/ошибки последующей сборки. Зависший callback не объявляется принудительно безопасным: все внутренние операции обязаны соблюдать request deadline.

Добавлены unit bounds/default-off/host split/source isolation/drain-order tests и actual runtime-assembly child на пустом каталоге с TLS и SELECT-only resolver. Он проверяет отсутствие operator/default-DB fallback, но не заменяет предыдущий actual command login fixture или полную two-project matrix. Основной ENV путь запуска двух реально подготовленных проектов остаётся предметом последующей приёмки.


V1 Luna: actual TestProjectRuntimeAssemblySQL и TestOperatorProfileSQLHTTPS (Linux ARM64, no SKIP) и security PASS; TLS verify-full/SCRAM deny/RedisDB15 подтверждены, свой стенд очищен. Task check/app race FAIL на ошибочном require.Same для function handler, lint contextcheck/cyclop/G104. Исправлены assertion, propagation uncancelled cleanup context/ошибка drain и общий typed-nil worker filter. V2 task check/app race PENDING. Повтор unrelated SQL/security без новых изменений гарантий не запрашивается.


Финал V3: task check (tests/lint) и app/config race PASS; manifest9 и ENV examples совпадают с main. V1 actual runtime assembly/operator SQLHTTPS и security PASS остаются evidence незатронутых гарантий. V2 omitted cfg compile failure исправлен в V3. Внешние provider/SMTP, полный two-project запуск, fleet/capacity/GC и UI не проверялись этим блоком; deployment флаг остаётся выключенным по умолчанию.
