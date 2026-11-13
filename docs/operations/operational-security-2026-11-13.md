# Эксплуатационная безопасность — приёмка 13 ноября 2026

Статус: **локальные standalone и multi-project credential recovery проверки завершены с указанными ограничениями; внешняя эксплуатационная приёмка не выполнена**. Второй из [трёх блоков старого плана](../planning/implementation.md#остаток-старого-плана-перед-u1--уточнение-12-ноября-2026). Пользователь разрешил продолжить и уточнил: backup/restore должны в будущем управляться из админки. Это зафиксировано в [U3.1](../planning/ui-management.md#u31-резервные-копии-и-восстановление-из-админки), management API/UI сейчас не реализуются.

## Итоговый отчёт — безопасность и эксплуатация

Итог на 13 ноября 2026: **согласованные локальные проверки завершены; полная production-приёмка не заявляется**. Новые проверки при составлении этого отчёта не запускались. UI, management backup API и production deploy не начинались.

### Что проверено и закрыто локально

| Область | Подтверждённый результат | Граница результата |
| --- | --- | --- |
| Статический анализ и зависимости | gosec: 0 issues; после согласованного обновления Go до 1.27.4 govulncheck: 0 достижимых уязвимостей и 0 в импортируемых пакетах; целевые HTTP tests и Linux/arm64 compile PASS | Скан на дату базы 11 ноября 2026, darwin/arm64; не pentest и не гарантия отсутствия всех уязвимостей |
| Исправление безопасности | Достижимая GO-2026-6859 устранена закреплением Go 1.27.4; production image из нового снимка собран и запущен локально | Уже работающие внешние deployment автоматически не обновлены |
| Резервная копия и восстановление БД | Штатный wrapper, pre_restore, проверка архива, миграции, grants, audit и healthcheck прошли на synthetic DB; traversal, corrupt archive, неверное подтверждение и занятый lock отклонены | Прежний отдельный снимок; это не одновременное восстановление всех БД production |
| Защита после восстановления | Целевой TestRestoreAuthStateSchema и SQL invalidation прошли; wrapper не открывает API автоматически | Потерянные после backup постоянные права/пароли/блокировки требуют отдельной сверки; SQL revoke не отзывает офлайн JWT сам по себе |
| Ключи и конфигурация | Синтетические project master key/bundle, scoped account root, JWT private/JWKS восстановлены; чтение ciphertext и проверка/создание подписи прошли; неверные keys/bindings отвергаются | Не восстановление настоящего vault, всех provider payloads или INITIAL_SETUP_SECRET |
| Живой standalone Auth | После восстановления файлов config/TLS/keys: readiness 200, register 201, login 200, защищённый /me 200 по trusted HTTPS | БД этого сценария новая мигрированная; пользовательский dump в этом прогоне не восстанавливался |
| HTTPS и изоляция | Правильные CA/hostname принимаются, неправильные отвергаются; живой API только 127.0.0.1; PG/Redis без host bindings; runtime SQL role ограничена | Проверено на собственной локальной fixture, не на внешнем сервере |
| Multi-project recovery доступа | Каталог с encrypted credentials восстановлен в свежую БД; новый штатный reader/registry открыл правильную project DB по verified TLS; чужая привязка отвергнута | Сама project DB сохранялась в fixture; её пользовательский dump и project HTTP flow здесь не восстанавливались/не запускались |

[Подробный security audit](security-audit-2026-11-10.md#подтверждение-исправления--принято-13-ноября-2026). Module-only GO-2026-5932 для неимпортируемого openpgp остаётся явно учтённой записью, не скрыта suppression. Миграции/grants проверены для текущей схемы; совместимость произвольных исторических схем не доказана.

### Что осталось и какие условия обязательны

1. **В реальном окружении:** HTTPS/ingress, DNS/firewall/trusted proxy, закрытые PG/Redis, раздельные credentials, реальная пересборка/обновление Go и доступность защищённого внешнего хранилища backups/keys. Локальный Docker inspect этого не подтверждает.
2. **Полное аварийное восстановление:** согласованное восстановление каталога и всех project DB с пользовательскими данными, SQL roles/ACL, ключами и конфигурацией; фактические RPO/RTO, потеря хоста/off-host recovery и история изменений доступа не измерены. Один dump не сохраняет внешние ключи и global SQL roles. В multi-project проверке database ACL и canonical reader grants переустанавливались явно.
3. **Перед открытием трафика после restore:** сверить актуальные пароли, роли, блокировки/удаления с независимой историей; выполнить session/proof invalidation и восстановить актуальное JWT trust на всех узлах/consumers по [runbook](jwt-recovery.md). Без этого восстановленный backup может вернуть утратившие актуальность полномочия.
4. **Реальные интеграции:** Google/Telegram/SMTP — при подключении их окружения. Полные browser/UI сценарии — после появления UI и отдельного согласования макета/стека.
5. **Границы evidence:** не проводились новый pentest, полный повтор функциональных suites, fleet-wide JWT recovery и полный project-user-data restore. Предельный RPS/длительный GC soak исключены пользователем из текущего обязательного остатка; существующие результаты не доказывают максимальную capacity.

Штатные CLI backup/restore есть. Управление ими из админки — только согласованный будущий [U3.1](../planning/ui-management.md#u31-резервные-копии-и-восстановление-из-админки), не реализованный UI/API. Проверочные временные ресурсы очищены, retained auth-mp8-luna сохранён. Реальные данные и секреты не использовались.

### Идентичность и evidence

- Security fix: снимок SHA256 `60e126964edb76b2a27f6fdba3753018317452fa93e0758fb6dd7fd336db2c0f`, receipt `/private/tmp/auth-security-go1274-summary.json`.
- Первый backup/restore: снимок `62aa46d25d70bdc7c2473cef5d47453fbabc773352cc736e48e4e1bfe9768d2a`, receipt `/private/tmp/auth-operational-security-20261113-summary.json`. Старый архив/его per-file manifest недоступны; PASS сохранён как исторический результат, идентичность нового исходника с ним не заявлена.
- Ключи/TLS, assembled standalone и multi-project: снимок `dd8529b625ad9612e60d8ad14161c655041c52418aac762352d283a6a01b8bc8`, HEAD `1c4fc8cb2834a745f7e16095235d68f78095c2b8`; receipts с суффиксами `tail-summary.json`, `final-summary.json`, `multiproject-summary.json` по общему префиксу `/private/tmp/auth-operational-security-20261113-`. Actual roots/команды/exits приведены ниже и в соответствующих логах. Manifest сверён Luna; main ранее сравнил 1625 relevant files без расхождений.

Этот Markdown хранит постоянную сводку. Полные receipts/logs в /private/tmp — временные артефакты, не долговременный архив evidence. Повторных проверок для смены статуса или подготовки сводки не было.

## Первичная проверка backup/restore

Receipt `/private/tmp/auth-operational-security-20261113-summary.json`, snapshot SHA256 `62aa46d25d70bdc7c2473cef5d47453fbabc773352cc736e48e4e1bfe9768d2a`:

- PASS: целевой `TestRestoreAuthStateSchema` на Go 1.27.4 и собственной disposable PostgreSQL fixture.
- PASS: штатный restore wrapper на синтетической БД — проверка архива, pre_restore копия, миграции, runtime grants, инвалидизация credentials, audit, healthcheck; API остался остановленным.
- PASS: отклонение traversal, неверного подтверждения, занятого lock и повреждённой checksum.
- PASS: production Compose config и Docker-сборка с `golang:1.27.4-bookworm`. Это не проверка реального ingress или runtime ports.
- Созданные Luna контейнеры, volumes и image tag удалены; сохранённый `auth-mp8-luna` не изменён.

Следующие локальные проверки завершены в разделах ниже. Исторические статусы NOT RUN читать с учётом последующих результатов; актуальные незакрытые условия перечислены в итоговой сводке выше.

## Что есть по исходникам

- `task backup` → `deploy/scripts/postgres-backup.sh`: custom-format pg_dump, временные файлы и публикация проверенной dump/checksum пары, archive preflight, flock, расписание24h и retention7 копий по умолчанию.
- `task restore` → `deploy/scripts/postgres-restore.sh`: точное подтверждение project:database, проверка архива до остановки, operation mutex, остановка API/migrate/backup, защитная pre_restore копия, восстановление, migrate up, reviewed runtime grants, `restore-auth-state.sql`, healthcheck. **API не включается автоматически.**
- Restore SQL отзывает sessions/refresh и одноразовые proofs, обновляет auth_version и пишет operational audit. [Recovery runbook](jwt-recovery.md) дополнительно требует current account/role/password reconciliation, новый JWT trust и проверку consumers до открытия traffic.
- Production Compose не публикует PostgreSQL/Redis ports; API bind — loopback, filesystem read-only, cap_drop/no-new-privileges, отдельный app env от credentials owner/migration/backup. Фактические bindings и локальный runtime впоследствии подтверждены в отдельных сценариях ниже.
- Go1.27.4 закреплён в go.mod/обоих Dockerfile; Linux/arm64 compile уже принята. Последующая production Docker-сборка и локальный запуск подтверждены ниже; реальный deploy не выполнялся.

## Границы backup/restore

Один pg_dump не содержит внешние encryption/signing keys и global SQL roles; роли/привилегии должны создаваться проверенным provisioning/grants workflow. Официальная справка: [pg_dump18](https://www.postgresql.org/docs/18/app-pgdump.html). Restore непроверенного внешнего архива способен исполнить SQL привилегированного источника; checksum подтверждает целостность, не доверие к создателю.

Текущий backup — архив БД в защищённом volume, не готовый зашифрованный off-host recovery package. Резервирование ключей/конфигурации, внешнее защищённое хранение и эксплуатационная доступность должны проверяться/настраиваться отдельно. Для теста допустимы только синтетические ключи и данные. Не читать/копировать реальные env, secrets или рабочие backups.

Восстановление point-in-time возвращает старые постоянные пароли/роль/блокировку, если изменения после backup не отражены в независимой истории. SQL-инвалидизация временных credentials сама эту историю не восстанавливает. Нельзя открывать traffic после одного SELECT1 или объявлять старый local JWT недействительным только из-за отзыва SQL session.

## Минимальная необходимая проверка

| Область | Нужное evidence | Чего не повторяем |
| --- | --- | --- |
| Backup/restore | Реальный canary round-trip на собственной disposable БД; checksum/traversal/corrupt/lock refusal; pre_restore и отказ автоматического запуска API | Полный инфраструктурный smoke/SMTP/JWT/MP7 suite |
| Security после restore | Целевой actual `TestRestoreAuthStateSchema` на собственной auth-j72 fixture либо достаточное прежнее evidence с точным scope; stale credentials не получают доступ; permanent-state reconciliation отдельно | Все остальные account/MFA/session regression roots |
| Ключи/конфигурация | Собственные synthetic key backup/recovery, связь ключей/БД, отсутствие plaintext в отчёте; wrong/missing key не обходится fallback. Непокрытые key/fleet recovery явно NOT RUN | Реальные keys/recovery/deploy и новый key-management feature |
| Upgrade/grants | Миграции/их повтор/реальный восстановленный current schema; несовместимость не открывает API; runtime без owner/DDL/superuser и восстановленные reviewed grants | Выдуманный upgrade неподдерживаемой исторической схемы/reset рабочей БД |
| Docker/TLS/ports | Изолированная сборка Go1.27.4 собственным image tag; inspect production config/role separation/no public SQL/Redis; TLS с корректным CA, без insecure bypass | Нагрузка, image tags/контейнеры пользователя и production deploy |

Все команды/стенды/cleanup выполняет Luna на неизменяемом снимке. Если изолированную destructive fixture нельзя безопасно переиспользовать, допустима одна собственная новая; foreign/retained DBs не сбрасывать. Применять существующие scripts/tests и минимальные временные overrides, не создавать новый production harness/service. Main исправляет только подтверждённые дефекты, затем Luna повторяет affected delta.

## Не закрывается локальным прогоном

Реальный ingress/firewall/DNS/proxy topology, disaster recovery хоста, off-host vault/backup storage, real SMTP/providers, fleet-wide JWT distrust и browser/UI acceptance требуют соответствующего окружения. Без него NOT RUN, а не PASS. Это условия production запуска, не повод повторять все старые локальные проверки.

Первичный receipt получен: `/private/tmp/auth-operational-security-20261113-summary.json`. Production restore/deploy и реальные данные не разрешены.

## Итог остаточной проверки Luna

Снимок SHA256 `dd8529b625ad9612e60d8ad14161c655041c52418aac762352d283a6a01b8bc8`, HEAD `1c4fc8cb2834a745f7e16095235d68f78095c2b8`. Luna сверила 1870 файлов manifest; main отдельно сравнил 1625 файлов internal/deploy/go.mod/go.sum с текущим деревом: изменений нет. Receipt `/private/tmp/auth-operational-security-20261113-tail-summary.json`, команды/exits — соседний `auth-operational-security-20261113-tail.log`.

- PASS: runtime recovery синтетического project master key/bundle, scoped account encryption root и JWT private/JWKS files. Сохранённые данные и подпись читаются/проверяются после восстановления; неверные/отсутствующие ключи, key ID, project/realm/purpose отвергаются. Старый JWT проверен после reload, новый подписан и проверен. Это проверка перечисленных механизмов, не восстановления реального vault/полной конфигурации приложения.
- PASS: проектный `internal/server/http.Run` с synthetic CA/certificate в контейнере без сети. Верный CA+localhost принят, неверный CA/hostname отвергнуты. Полный Auth handler/живой deployment endpoint не запускался.
- PASS: у собственной PostgreSQL/Redis fixture реальные host bindings пусты; внутренние подключения работают. Synthetic runtime role не superuser и не может создавать schema; owner credentials отделены. Loopback API подтверждён только rendered Compose, не живым API container.
- Созданные fixture/сеть/volumes/временные keys/tests/cache удалены; snapshot/manifest сохранены. Retained auth-mp8-luna не изменён. Новых дефектов в выполненных проверках не выявлено.

Прежние backup/restore/build PASS относятся к другому снимку: его per-file manifest недоступен, поэтому перенос идентичности не заявлен, проверки не повторялись.

**NOT RUN:** полная сборка Auth с восстановленной конфигурацией, подключение project DB через восстановленный credential, recovery INITIAL_SETUP_SECRET и отдельных provider payloads, живой API port, внешний ingress/firewall/vault, реальные keys/data и fleet-wide JWT trust. Полная эксплуатационная готовность не объявлена; соответствующие условия запуска остаются открыты. Потерянные после backup постоянные права/пароли требуют reconciliation до открытия трафика.

## Финальный локальный запуск Auth

Luna проверила тот же snapshot `dd8529b625ad9612e60d8ad14161c655041c52418aac762352d283a6a01b8bc8`. Receipt `/private/tmp/auth-operational-security-20261113-final-summary.json`, компактный лог `/private/tmp/auth-operational-security-20261113-final.log`.

- PASS: production image из снимка собран; синтетический комплект config/TLS/keys архивирован и распакован; применены миграции, canonical runtime grants и restore-auth-state.sql до запуска настоящего API.
- PASS: readiness 200, регистрация 201 с session cookie, вход 200 с session cookie, защищённый `/api/v1/auth/me` 200. HTTPS с synthetic CA и localhost SAN, без insecure bypass.
- PASS: живой API binding `127.0.0.1:18443 -> 18443`; у PostgreSQL и Redis host bindings пусты.
- PASS: удалены только собственные fixture containers/network/volumes/image и временные config/keys/cookies; snapshot/manifest сохранены, auth-mp8-luna не изменён.

**Точное покрытие:** standalone (`PLATFORM_ENABLED=false`), восстановление файлового комплекта и запуск на новой мигрированной БД без исходных пользователей. Это не новый полный DB dump/restore round-trip: прежняя проверка БД сохраняется отдельным историческим evidence своего снимка. Crypto recovery/отрицательные keys, CA/hostname и isolation suites повторно не выполнялись. Новый end-to-end сценарий закрывает живой standalone API и файловую конфигурацию, но не multi-project recovery.

**Остаётся NOT RUN:** динамическое подключение проектной БД через восстановленные encrypted credentials, реальная внешняя доставка/ingress/firewall/vault, production data restore и fleet-wide reconciliation/JWT distrust. Полную эксплуатационную готовность всех режимов не объявляем.

## Восстановление доступа к проектным БД — multi-project

Luna: PASS с ограничениями, snapshot `dd8529b625ad9612e60d8ad14161c655041c52418aac762352d283a6a01b8bc8`. Receipt `/private/tmp/auth-operational-security-20261113-multiproject-summary.json`, компактный лог рядом с суффиксом `multiproject.log`. Actual root: временный `TestRecoveredProjectRuntimeSQL`, `go test -run ^TestRecoveredProjectRuntimeSQL$ -count=1 -v ./internal/app/projects/tests`, Go 1.27.4, GOPROXY=off, exit 0, без skips.

- Существующий managed preparation workflow подготовил два synthetic проекта. Каталог с encrypted credentials выгружен и восстановлен в новую отдельную catalog DB; ciphertext/format/key ID совпали.
- После восстановления повторно применены database-level `REVOKE CREATE,TEMP FROM PUBLIC` и canonical runtime-reader grants. Эти права не следует считать автоматически восстановленными одним DB dump.
- Из восстановленного каталога и перечитанных synthetic master key/config создан новый `projectapp.Open`: отдельные catalog pool/reader/Registry, без переиспользования прежнего pool.
- Штатные `RuntimeCredentialReader.LoadDatabaseCredential` и `Registry.Use` открыли нужную проектную БД по verified TLS. Canary подтвердил project identity, ограниченную runtime SQL role (не superuser, без database CREATE).
- Чужой project ID с восстановленной привязкой первого проекта отклонён до callback.
- Собственные fixture/keys/dump/cache/probe test удалены; snapshot/manifest и чужие ресурсы сохранены. Ранее пройденные suites не повторялись.

**Граница результата:** восстановлены каталог и encrypted credential state; сама project DB оставалась в synthetic fixture. Dump/restore пользовательских данных проекта и project HTTP flow в этом сценарии не выполнялись. Локальный gap доступа через восстановленные credentials закрыт; это не доказательство полного одновременного восстановления всех БД, host disaster recovery или production fleet. Внешние условия и reconciliation/JWT trust из runbook остаются обязательными условиями запуска. Этот раздел уточняет прежние NOT RUN multi-project credential runtime выше.
