# Подготовка настроек и первого администратора проекта

MP3-onboarding-preparation,20 октября2026. Opt-in `project-prepare -schema -secrets -password -onboarding` после [установки технического пароля](project-secrets-preparation.md#установка-технического-пароля--20-октября). Без -password новый флаг отвергается до подключений. Успех возвращает `stage: onboarding_prepared`, не ready/созданного администратора. Credentials/setup token/digest не включаются в ответ.

## Что подготавливается

- `auth.auth_settings`: парольный метод включён, public registration/Google/Telegram registration выключены; email OTP/Google/Telegram/JWT exchange/native выключены. Password email verification — disabled: при закрытой регистрации это не делает чужой email verified; отдельный setup подтверждает почту первого администратора существующим кодом. Изменение политики позже — защищённое управление настройками, не повтор bootstrap.
- `auth.initial_setup`: только singleton и SHA256-digest независимого project setup secret. Нет пользователя, email/password hash, role assignment, MFA factor, pending intent или initialized marker. Общего/default пароля администратора нет.
- `project_meta.identity`: configuration_prepared=true и matching setup_operator_hash. Эти поля, настройки и setup pin коммитятся атомарно. Existing private schema creation расширена без новой migration; старому project_meta нужен controlled forward upgrade. Auth migration/grants не менялись, initial bootstrap поверх активной БД запрещён.

Bootstrap setup secret уже находится внутри encrypted catalog bundle, независим от DB password/project encryption key. `credentials.SetupProof` раскрывает только digest+binding, fmt/JSON редактированы; raw setup secret/другие ключи не возвращаются. `ReadSetupProof` использует тот же bounded current-authority transaction/AEAD decoder, что и DB reader, без двойного decrypt/нового шифрования. На ошибке/failed commit наружу не возвращается proof. Digest тоже не публиковать.

## Гарантии выполнения и повторов

1. Trusted schema binding, restricted target profile, receipt установки пароля, actual sealed DB/NOLOGIN runtime/ACL/OIDs проверяются **до** временного открытия БД.
2. Общий существующий lifecycle schema/onboarding открывает доступ только executor, проверяет shared marker/actual OIDs на новом соединении и повторно attests schema/role. Для успеха обязателен reseal; cleanup установлен до неоднозначного открытия. При outage/kill bounded cleanup может не завершиться: возможен только прежний executor-only crash-open, продолжение через ownership journal, не ready. Runtime LOGIN/CONNECT не включаются.
3. Project transaction держит schema transaction lock → существующий Access lock → private identity row; settings/setup helpers используют тот же Access lock. Реальные users/roles, unmarked settings/setup, неправильные binding/proof или утрата подготовленных rows дают отказ, не adoption/reset.
4. Используются существующий SQL initializer настроек (новый transaction-owned entry point) и существующий setup singleton lock/pinning. Дубликатов setup/password/MFA сценария, новых crypto primitives/dependencies/ENV/HTTP/Swagger нет.
5. Сохранённые settings должны иметь исходную version1/политику, setup pin — тот же digest. Replay не переписывает settings/setup/marker, не меняет pending intent и не открывает завершённый setup. Drift не сбрасывается к defaults; missing prepared setup/settings не воссоздаются автоматически.
6. Current catalog authority проверяется до открытия, перед project commit и после reseal. При позднем suspend могут остаться начальные записи в закрытой БД; успех/ready/access не публикуются. Разные БД не превращаются в общую атомарную транзакцию.

Вся операция bounded20s, project rollback/close1s и access cleanup3s; прежний target session lock сохраняется, обычный invocation использует до3 SQL connections без нового пула/workers. SQL presence checks — EXISTS, нет сканирования пользователей для подсчёта/импорта и нет изменения Auth hot path. Capacity/GC не измерялись.

## Изолированный HTTP-профиль onboarding

`router.NewProjectOnboarding` принимает только доверенный origin проекта, существующий SetupHandler, callback текущего допуска, HTTP capacity/proxy policy и logger. Здесь нет общего набора Auth handlers или наследования конфигурации платформы. Профиль пока **не подключён** к основному серверу.

Разрешены только `POST /api/v1/setup/start` и `POST /api/v1/setup/complete`. Повторно используются существующие setup handler/DTO/error mapping, ограничения размера JSON и проверка `X-Setup-Token`. Новый профиль не реализует второй setup flow и не меняет требования email/MFA существующего сервиса.

- Требуются TLS и точное совпадение Host, включая настроенный порт. X-Forwarded-Host/Forwarded/X-Forwarded-Proto не заменяют эти проверки; deployment с TLS termination потребует отдельно согласованного trusted ingress, plaintext fallback здесь отсутствует.
- Для обоих POST обязателен единственный точный project Origin. Cross-origin CORS не включён; OPTIONS и остальные методы не дают доступ к setup. Platform Origin не разрешается автоматически. Это same-origin профиль, не готовое подключение будущей общей админки.
- На каждом допустимом POST вызывается `Admit(ctx)`: false →404, ошибка/отменённый context →503 без деталей каталога; положительный ответ не кешируется. Callback обязан проверять актуальные project/reservation/version/generation и readiness для onboarding, соблюдать общий request deadline. Его production-реализация ещё не подключена; unit fake не подтверждает SQL authority/fencing.
- Неверные Host/Origin, неизвестные маршруты и неподдерживаемые методы не вызывают catalog callback или SetupHandler. Login/register/recovery/roles/settings/platform/JWKS/Swagger/health не регистрируются. Ответы не кешируются, собственных session cookies профиль не создаёт.
- Используется существующий bounded HTTP admission; бюджет относится к экземпляру handler, а не ко всему процессу/fleet. Дальнейший dispatcher обязан учитывать суммарные бюджеты.

Проверка допуска — до выполнения setup, не распределённая транзакция с project SQL. Уже допущенный запрос потенциально завершится после suspend; публикация ready и дальнейший допуск требуют отдельного fencing/readiness протокола. Один успешный callback не разрешает обычные Auth routes.

## Что ещё не включено

Этот этап **не запускает UI и не публикует project setup endpoint**. Доставка raw setup secret доверенному владельцу/сборка runtime с собственными encryption keys/доступ оператору требуют отдельного протокола, не ссылки с секретом в URL или CLI stdout. Не копировать credentials платформенного администратора в проект и не трактовать platform session как SSO.

Завершение первого администратора переиспользует [существующий setup](initial-setup.md): email proof/password policy/MFA/recovery и durable initialized marker; SMTP/provider/MFA readiness не выдумывается. Текущий setup требует MFA, выбор обязательности ещё в отдельном A6.3m. Configuration prepared не означает готовый SMTP или существующего администратора. Далее согласовать и реализовать activation/onboarding-only admission, реальное runtime connection/SQL grants probe, first-admin/configuration readiness и binding/ready. Не открывать обычные Auth endpoints только на основании этого marker.

## Проверки

[History/evidence](../planning/history.md#результат-mp3-onboarding-preparation--20-октября-2026): formatter/task check/race/security/build и actual PostgreSQL command regression. Проверены safe defaults/no user, atomic marker-failure rollback, authority loss, immutable three-row replay, wrong pin/policy, orphan/lost setup refusal, LOGIN-role rejection до открытия. SQL тест также повторяет прежние storage/schema/credentials/password/API guards и TCP SCRAM на disposable maintenance-БД. Полный existing standalone setup HTTPS/SMTP/TOTP/fleet/restore/rotation/load/GC не проверялся этим этапом; unit/race без ENV не live SQL sign-off.
