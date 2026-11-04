# Защищённые credentials проекта — MP3-secrets-storage

19 октября 2026. `project-prepare -schema -secrets` сохраняет независимый зашифрованный bootstrap-набор после успешного [schema stage](project-schema-preparation.md). Это **не активация runtime**: пароль пока не установлен в PostgreSQL, роль остаётся NOLOGIN без CONNECT, БД sealed, каталог provisioning без ready binding. Не создаются администратор/UI/провайдеры, существующая standalone Auth БД не переносится.

## Состав набора

| Значение | Генерация и назначение |
| --- | --- |
| Database password | 32 random bytes, raw base64url; для будущей установки runtime credential |
| Project encryption key | Независимые32 random bytes, standard base64; соответствует текущему project EMAIL_OUTBOX_KEY, с существующими scoped purposes для outbox/MFA/settings |
| Initial setup secret | Ещё32 random bytes, raw base64url; не равен project encryption key, не включает setup автоматически |
| Signing key + kid | ES256/P-256, PKCS8 PRIVATE KEY PEM и random kid; JWT не включается и ключ/JWKS не публикуются |

Генерация bootstrap-набора — crypto/rand/ecdsa/x509. Google/Telegram/SMTP credentials не выдумываются. Package `internal/admin/projects/credentials` генерирует/проверяет encrypted payload и открывает ограниченный тип DatabaseCredential для доверенного provisioning reader. Plaintext не сериализуется в CLI response и не передаётся PostgreSQL. Для отдельной установки SCRAM password с разрешения пользователя добавлена xdg-go/scram v1.2.0; активация ещё впереди.

## Operational master key

В [отдельном ENV-примере](../../deploy/examples/project-prepare.env.example):

- `PROVISIONER_MASTER_KEY` — новый случайный32-byte standard-base64 key. Сохраняется в защищённом окружении executor/внешнем secret storage, **не в БД и не в репозитории/UI**; не переиспользовать platform EMAIL_OUTBOX_KEY.
- `PROVISIONER_MASTER_KEY_ID` — явный non-secret ID вида `root-1` (lowercase letter, затем letters/digits/hyphen, до32 символов). Указывает на конкретный master key; это не сам ключ.

Новый -secrets требует -schema. Пустой/невалидный/нулевой master key и неверный key ID отвергаются до подключения/записи intent. Нет автоматической генерации master key, чтения неизвестного старого ключа или fallback на платформенный outbox key. Без -secrets master ENV не требуется; прежние sealed/schema modes сохранены.

```sh
go run ./cmd/project-prepare \
  -project a2000000-0000-4000-8000-000000000001 \
  -operation b2000000-0000-4000-8000-000000000001 \
  -version 1 -generation 1 -schema -secrets
```

UUID — пример. При повторе используются те же flags/expected revisions, как в catalog Reserve. Успех возвращает только `stage: secrets_stored` и прежние project/schema metadata, без ciphertext/password/keys/key material. Статус означает durable encrypted storage, не рабочую авторизацию нового проекта.

## Шифрование и ownership binding

Переиспользован `internal/infra/secretbox.NewScoped`: AES-256-GCM с новым96-bit random nonce. AAD содержит purpose `project-secrets`, format version1, master key ID и trusted binding: realm/project/reservation UUID, storage target, database/owner/runtime OID, Auth schema version. Binding выдаёт target только после успешной установки/проверки схемы и reseal; catalog port сверяет realm/project/reservation/target с trusted repository context.

Перенос payload между проектами/платформами/резервациями/targets/OIDs/версиями не делает его пригодным. Дешифрование проверяет формат и P-256 material; unknown version/key ID/tamper/wrong root — безопасная одинаковая ошибка без key/cipher/driver details. Не используются ручной AES/SCRAM/KDF или plaintext ALTER ROLE PASSWORD. Ограничение payload128–8192bytes проверяется схемой и codec. AES-GCM nonce budget относится ко всему master key; бесконечное использование одного ключа не предполагается.

Root и plaintext остаются в памяти процесса, как и другие service secrets. Временные byte buffers очищаются по возможности; Go strings/GC/AES schedules не дают гарантированного zeroization. Не логировать Codec/material, не включать process/core dumps/unsafe debug tracing. Catalog SQL получает ciphertext/binding; отдельный target password stage — verifier и fingerprint, не исходный пароль. Verifier тоже секретный: ограничить SQL/audit/query tracing и доступ к логам; отсутствие plaintext не делает их публичными. Полная host/heap/dump защита и ресурсная приёмка отдельно.

## Сохранение и повторы

`platform.project_secrets`: одна immutable row на project UUID, с reservation/target/OIDs/schema/format/key-ID/ciphertext/createdAt. Нет runtime endpoint чтения/экспорта. `project_preparations.secrets_created` — постоянный ownership marker, не audit с180d retention.

1. Повторная проверка restricted preparation SQL profile. Одна bounded Read Committed transaction берёт locks в том же порядке, что Reserve: initialized realm → project → preparation.
2. Общий current-preparation SQL guard проверяет enabled/provisioning/current version/generation/operation/nonce/target/no-binding под этими locks. Это не отдельный устаревший snapshot; lifecycle mutation ждёт до commit/rollback.
3. При отсутствии row и false flag генерируется набор, шифруется, выполняются INSERT и flag=true в **одной transaction**. RETURNING binding/ciphertext проверяются до commit; ошибка flag update/AEAD/metadata откатывает всё.
4. При существующих row+true flag проверяются прежние binding/version/key ID/ciphertext, без генерации/UPDATE. Четыре concurrent callers сериализованы per project и получают один durable набор; другие проекты не блокируются эксклюзивным глобальным catalog lock.
5. Missing row + retained true flag, row + false flag, несовпадение OIDs/nonce/target или непригодный ciphertext — отказ, не repair/reset/новые ключи. Полная потеря одновременно marker/row/catalog history после restore не доказывается этим guard: сохраняется обязательный restore/fencing runbook.

Role обычного platform API не получает даже ciphertext SELECT, включая column-only grants; startup отвергает лишний доступ и UPDATE creation flag. Preparation LOGIN получает только SELECT/INSERT secret row + UPDATE flag, не UPDATE/DELETE/TRUNCATE ciphertext и не INSERT(created_at). Дополнительно в затронутых catalog/API профилях закрыт пропущенный REPLICATION attribute; elevated role memberships также проверяются.

Всё добавлено в исходную catalog000001/preparation grants, без нового migration-файла. Старой установке нужен controlled forward schema/grants upgrade, не replay initial migration/сброс данных. Ownership markers и ciphertext не очищаются обычным session/security-audit retention.

## Типизированное чтение DB credential — 20 октября

`PreparationRepository.ReadDatabaseCredential` — внутренний provisioning port, не HTTP endpoint и не online runtime registry. Требует restricted preparation SQL credential и правильный master key. Возвращает только DatabaseCredential с привязкой и явным `Password()`; setup/encryption/signing keys через этот контракт не раскрываются. fmt/String/GoString/JSON представления типа редактированы; явный Password() предназначен только для доверенного connection/installation кода, его нельзя логировать. Это не защита от отладчика/reflection/компрометации процесса и не гарантированное zeroization.

Тот же3s budget/1s rollback и lock order realm → project → preparation, что у writer. Проверяются initialized realm, current version/generation/operation/desired state, reservation/target/no-binding, retained creation flag, полная metadata binding и AEAD. Неверный ключ/tamper/missing row/stale state дают ошибку и пустой credential. Нет генерации, INSERT, UPDATE ciphertext или нового material. Возврат только после успешного commit; cancelled/blocked transaction не выдаёт секрет.

**Результат — snapshot на момент чтения, не разрешение на будущий LOGIN/CONNECT/ready.** Locks отпущены при возврате; следующая стадия обязана отдельно обеспечить актуальную authority/fencing/target attestation перед side effect и публикацией доступа. Нельзя проверять только сохранённый Binding и считать, что поздний suspend не имеет значения. В ordinary API нет reader/root key; CLI не экспортирует пароль. Live SQL проверяет repeat read, stale generation/version/operation/project/target/OID, wrong root/tamper/flag/lost row, ожидание конкурентного UPDATE с bounded cancellation и отказ после suspend. Reader не подтверждает будущий password authentication.

На этапе reader установка пароля ещё не выполнялась: [исторические проверки и ограничения](../planning/history.md#результат-mp3-credentials-reader--20-октября-2026). Отдельная стадия установки реализована ниже; LOGIN/CONNECT остаются закрытыми.

## Установка технического пароля — 20 октября

Опциональный `project-prepare -schema -secrets -password` читает сохранённый DB credential и вызывает Target.InstallPassword. `-password` без `-secrets` отвергается до подключений. Успех — только `stage: password_installed` с прежними metadata; пароль/verifier/fingerprint не выводятся. Без флага прежние stages не устанавливают пароль.

Генератор использует согласованную **github.com/xdg-go/scram v1.2.0**, включая необходимые pbkdf2 v1.0.0/stringprep v1.0.4; версии существующих модулей не понижались. SHA256.NewClient/GetStoredCredentialsWithError, random16-byte salt,4096 iterations, стандартный PostgreSQL SCRAM-SHA-256 format. Пароль — сгенерированные256bit raw-base64url ASCII, не человеческий пароль; проверяется формат/размер, ошибки библиотеки заменяются безопасной ошибкой. Собственной PBKDF2/HMAC/SCRAM реализации и нового network service нет. Основной Auth API не импортирует эту библиотеку по dependency graph.

Исходный пароль не включается в SQL/parameters: передаётся уже готовый verifier. Это поддерживает [PostgreSQL](https://www.postgresql.org/docs/18/sql-createrole.html); password NOLOGIN-роли можно установить до её активации. Dynamic ALTER ROLE содержит только серверное sanitized имя и fixed/base64 verifier, но verifier по-прежнему нельзя логировать как публичную информацию. Для production сохраняются verify-full/TLS и запрет unsafe query tracing; тест TCP ниже не подтверждает TLS.

Bounded10s операция/1s rollback; отдельная maintenance session продолжает держать прежний target lock. Требуются успешная schema attestation и точный credential binding, restricted executor profile, current catalog authority до target transaction, перед commit и после commit. Под row lock журнала проверяются nonce/OIDs/generation/schema_started; actual database name/owner/shared marker/sealed ACL и runtime OID/name/NOLOGIN/без elevated attributes/memberships/CONNECT. После ALTER повторно проверяются target metadata; password и journal update коммитятся атомарно.

В initial storage-target.sql добавлены только `runtime_oid` и `password_fingerprint` с парным CHECK,32-byte fingerprint и column UPDATE grants executor. Fingerprint = SHA256 случайного256bit DB password, не схема хранения человеческих паролей и не замена SCRAM. При replay matching fingerprint/OID возвращается без ALTER ROLE/UPDATE; расхождение — отказ, не rotation/repair. Schema stage также больше не переписывает уже true schema_started: matching row/generation проверяются под прежним lock. Старому target нужен controlled forward schema/grants upgrade; новую миграцию/автоматический reset не добавляли.

Catalog и target — разные БД, общей транзакции нет. Suspend между проверками может оставить **установленный пароль в закрытой БД с NOLOGIN**, но финальная authority проверка не даст успешный stage; это не публикация доступа. LOGIN/CONNECT/ready требуют отдельного activation/fencing протокола. Receipt не доказывает, что внешний DBA впоследствии не сменил/обнулил pg_authid password: глобальное чтение pg_authid executor не выдаётся. Финальная проверка реального runtime connection, reconciliation/restore/rotation остаются обязательными; source bootstrap нельзя повторять поверх активного runtime.

Live SQL: rollback при journal failure и authority loss до commit, безопасный отказ после commit, immutable verifier/receipt replay, fingerprint mismatch и отсутствие plaintext в SQL/args по query tracer. На отдельной disposable maintenance-БД синтетическому runtime временно разрешён LOGIN/CONNECT **только тестом**, wrong-password отказ и correct-password TCP authentication PASS; затем NOLOGIN/CONNECT revoke. Project DB остаётся sealed. Loopback HBA использует trust, поэтому тест требует явный `AUTH_STORAGE_TEST_SCRAM_HOST` с password-enforcing HBA; без него только этот drill помечается NOT RUN, не PASS. HBA стенда не меняли. [Evidence](../planning/history.md#результат-mp3-password-installation--20-октября-2026).

## Rotation и восстановление

Смена master key/key ID в ENV **не ротирует** существующие записи. Replay остановится; не удалять marker/row и не генерировать новый project key для обхода ошибки. Вернуть соответствующий сохранённый key ID/master и согласованный catalog backup.

Будущая master rotation — отдельная offline/ограниченная операция с old+new keys: открыть прежний материал, rewrap **те же** project secrets с новым AAD/key ID, проверить и атомарно заменить запись под authority locks. Обычному writer UPDATE намеренно не выдан; команды rotation/ключевого ring/fallback в этом блоке нет. Не уничтожать старый key до проверки всех записей, consumers и читаемости retained backups. Процедура deployment/recovery и автоматизация rotation остаются gate MP3.5.

JWT signing rotation — отдельный существующий JWT lifecycle, не «повторить bootstrap». Schema/credential upgrades также требуют явного versioned rewrap/transition, а не смены binding или initial SQL поверх живых данных. Master key хранить и резервировать отдельно от DB dump; без него ciphertext невозможно восстановить. Реальные keys/restore/rotation этим этапом не выполнялись.

## Проверки и следующий шаг

Unit: независимые key sets, private-key format, AEAD binding каждого поля, tamper/unknown version/key ID/wrong root, bounded payload, безопасные ошибки и ранний CLI отказ без master key. SQL: actual restricted preparation/API LOGIN, четыре concurrent first writes/one row, no-UPDATE replay (xmin), atomic INSERT+flag rollback, неверные root/key ID без переписывания row, wrong OID, lost ciphertext refusal, API column-grant/flag/REPLICATION guards. Прежний schema rollback/replay/runtime permission/marker/concurrent suspend flow включён в тот же SQL test.

Команды/evidence/cleanup/NOT RUN — [storage history](../planning/history.md#результат-mp3-secrets-storage--19-октября-2026) и [password history](../planning/history.md#результат-mp3-password-installation--20-октября-2026). Обычный race не SQL-race. TCP password authentication проверен на disposable maintenance-БД, не готовом project runtime/TLS. Process crash/restore/rotation/secret registry consumer/fleet/load/GC не проверены. До3 SQL connections на обычный invocation,3s catalog stages/10s password stage с1s cleanup; crypto только при provisioning, не на каждом Auth request. Capacity не измерена.

После password stage выполнена [подготовка defaults/setup pin](project-onboarding-preparation.md), не создание администратора. Далее отдельный протокол LOGIN/CONNECT/runtime probe/onboarding admission и first-admin/configuration readiness/binding/ready только после durable matching material/current authority. Полный runtime registry/consumers всех ключей, master rotation и весь MP3.5/MP3/readiness не закрыты; UI не начинать.
