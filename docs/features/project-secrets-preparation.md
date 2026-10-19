# Защищённые credentials проекта — MP3-secrets-storage

19 октября 2026. `project-prepare -schema -secrets` сохраняет независимый зашифрованный bootstrap-набор после успешного [schema stage](project-schema-preparation.md). Это **не активация runtime**: пароль пока не установлен в PostgreSQL, роль остаётся NOLOGIN без CONNECT, БД sealed, каталог provisioning без ready binding. Не создаются администратор/UI/провайдеры, существующая standalone Auth БД не переносится.

## Состав набора

| Значение | Генерация и назначение |
| --- | --- |
| Database password | 32 random bytes, raw base64url; для будущей установки runtime credential |
| Project encryption key | Независимые32 random bytes, standard base64; соответствует текущему project EMAIL_OUTBOX_KEY, с существующими scoped purposes для outbox/MFA/settings |
| Initial setup secret | Ещё32 random bytes, raw base64url; не равен project encryption key, не включает setup автоматически |
| Signing key + kid | ES256/P-256, PKCS8 PRIVATE KEY PEM и random kid; JWT не включается и ключ/JWKS не публикуются |

Генерация — crypto/rand/ecdsa/x509, без новой зависимости или собственного криптопротокола. Google/Telegram/SMTP credentials не выдумываются. Package `internal/platform/project/credentials` имеет только генерацию encrypted payload/проверку; plaintext material не возвращается из catalog port, не сериализуется в CLI response и не передаётся PostgreSQL. Runtime reader/установка DB password/активация — следующий блок.

## Operational master key

В [отдельном ENV-примере](../../deploy/project-prepare.env.example):

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

Root и plaintext остаются в памяти процесса, как и другие service secrets. Временные byte buffers очищаются по возможности; Go strings/GC/AES schedules не дают гарантированного zeroization. Не логировать Codec/material, не включать process/core dumps/unsafe debug tracing; SQL получает только ciphertext/публичные binding metadata. Полная host/heap/dump защита и ресурсная приёмка отдельно.

## Сохранение и повторы

`platform.project_secrets`: одна immutable row на project UUID, с reservation/target/OIDs/schema/format/key-ID/ciphertext/createdAt. Нет runtime endpoint чтения/экспорта. `project_preparations.secrets_created` — постоянный ownership marker, не audit с180d retention.

1. Повторная проверка restricted preparation SQL profile. Одна bounded Read Committed transaction берёт locks в том же порядке, что Reserve: initialized realm → project → preparation.
2. Общий current-preparation SQL guard проверяет enabled/provisioning/current version/generation/operation/nonce/target/no-binding под этими locks. Это не отдельный устаревший snapshot; lifecycle mutation ждёт до commit/rollback.
3. При отсутствии row и false flag генерируется набор, шифруется, выполняются INSERT и flag=true в **одной transaction**. RETURNING binding/ciphertext проверяются до commit; ошибка flag update/AEAD/metadata откатывает всё.
4. При существующих row+true flag проверяются прежние binding/version/key ID/ciphertext, без генерации/UPDATE. Четыре concurrent callers сериализованы per project и получают один durable набор; другие проекты не блокируются эксклюзивным глобальным catalog lock.
5. Missing row + retained true flag, row + false flag, несовпадение OIDs/nonce/target или непригодный ciphertext — отказ, не repair/reset/новые ключи. Полная потеря одновременно marker/row/catalog history после restore не доказывается этим guard: сохраняется обязательный restore/fencing runbook.

Role обычного platform API не получает даже ciphertext SELECT, включая column-only grants; startup отвергает лишний доступ и UPDATE creation flag. Preparation LOGIN получает только SELECT/INSERT secret row + UPDATE flag, не UPDATE/DELETE/TRUNCATE ciphertext и не INSERT(created_at). Дополнительно в затронутых catalog/API профилях закрыт пропущенный REPLICATION attribute; elevated role memberships также проверяются.

Всё добавлено в исходную catalog000001/preparation grants, без нового migration-файла. Старой установке нужен controlled forward schema/grants upgrade, не replay initial migration/сброс данных. Ownership markers и ciphertext не очищаются обычным session/security-audit retention.

## Rotation и восстановление

Смена master key/key ID в ENV **не ротирует** существующие записи. Replay остановится; не удалять marker/row и не генерировать новый project key для обхода ошибки. Вернуть соответствующий сохранённый key ID/master и согласованный catalog backup.

Будущая master rotation — отдельная offline/ограниченная операция с old+new keys: открыть прежний материал, rewrap **те же** project secrets с новым AAD/key ID, проверить и атомарно заменить запись под authority locks. Обычному writer UPDATE намеренно не выдан; команды rotation/ключевого ring/fallback в этом блоке нет. Не уничтожать старый key до проверки всех записей, consumers и читаемости retained backups. Процедура deployment/recovery и автоматизация rotation остаются gate MP3.5.

JWT signing rotation — отдельный существующий JWT lifecycle, не «повторить bootstrap». Schema/credential upgrades также требуют явного versioned rewrap/transition, а не смены binding или initial SQL поверх живых данных. Master key хранить и резервировать отдельно от DB dump; без него ciphertext невозможно восстановить. Реальные keys/restore/rotation этим этапом не выполнялись.

## Проверки и следующий шаг

Unit: независимые key sets, private-key format, AEAD binding каждого поля, tamper/unknown version/key ID/wrong root, bounded payload, безопасные ошибки и ранний CLI отказ без master key. SQL: actual restricted preparation/API LOGIN, четыре concurrent first writes/one row, no-UPDATE replay (xmin), atomic INSERT+flag rollback, неверные root/key ID без переписывания row, wrong OID, lost ciphertext refusal, API column-grant/flag/REPLICATION guards. Прежний schema rollback/replay/runtime permission/marker/concurrent suspend flow включён в тот же SQL test.

Команды/evidence/cleanup/NOT RUN — [history](../planning/history.md#результат-mp3-secrets-storage--19-октября-2026). Обычный race не SQL-race. Не проверены реальный TCP/TLS/password authentication для нового DB credential, process crash/restore/rotation/secret registry consumer/fleet/load/GC. До3 SQL connections на обычный invocation, один3s catalog save с1s cleanup; crypto только на создании/проверке provisioning, не на каждом Auth request. Capacity не измерена.

Далее: typed runtime reader, безопасная установка DB credential без plaintext SQL/logs, LOGIN/CONNECT только после durable matching material/current authority и readiness, независимые runtime/configuration/first admin, binding/ready. Master storage foundation готова, весь MP3.5/MP3/readiness не закрыты; UI не начинать.
