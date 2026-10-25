# Загрузка конфигурации проектного Auth

MP4.1a, 25 октября2026. Первый блок production loader, до сборки feature runtime. Реализация и локальные проверки Luna V1/V2 PASS.

## Решение до реализации

- Ближайший потребитель — сборка существующих Auth services для selected project. Вход — trusted runtime Key из каталога; не Host/slug/claims клиента. Loader не является HTTP API или проверкой полномочий оператора.
- Из project_secrets выдавать только data-encryption key в отдельном redacted типе. Не переиспользовать onboarding result с setup secret и не возвращать database password/signing material. Root остаётся связанным с realm/project/reservation/target/OID/schema AEAD; feature purpose и Redis scope добавляет существующая realm assembly.
- Catalog read использует те же точные snapshot/privilege guards, что работающий DB credential loader. Не дублировать их SQL в разных ветках.
- Auth policy читается из проектной БД через существующий bounded registry lease и readonly RepeatableRead transaction с runtime identity/profile check. Никакой Initialize, ENV fallback, подготовки пользователей или изменения настроек.
- До выдачи результата ещё раз проверить current catalog key/reader profile. Suspend/rebind/change epoch во время чтения отбрасывает результат. Вся операция ограничена общим timeout3s; строки/транзакции/lease освобождаются до возврата.
- Это входные данные сборки, не admission/authorization/cache/capabilities. Policy snapshot может потребовать повторной проверки перед использованием при изменении версии. Credential rotation обязана менять runtime epoch; loader не вводит отдельный скрытый rotation protocol.
- Не добавлять новые таблицы/миграции/ENV/dependencies, кеш, workers, новые публичные routes или фиктивную readiness. Managed provisioning/ready publication имеет отдельные stage guards; normal loader работает только для ready/enabled ресурсов.

## Проверки

Unit crypto: выдаётся правильный узкий ключ, redaction, wrong binding/key/version/corruption и отсутствие наследования чужого ключа. Actual command SQL: stored policy/key без UPDATE, stale key/realm/profile/состояние, missing policy fail-closed; итоговые fixtures должны сохранить исходные данные и xmin соседних replay tests. task check и affected race/security — Luna на frozen snapshot.

## Дальше

MP4.1b: собрать feature services с project dependencies без увеличения SQL pools и без передачи leased connection в асинхронную работу. После этого — реальная delivery/provider/token assembly, версия настроек и invalidation, ограниченные workers, отдельная публикация readiness/host routing. Пустые capabilities текущего platform settings bridge этим блоком не меняются; UI не начинается.

## Реализованный контракт

`RuntimeCredentialReader.LoadAuthConfiguration(ctx,key,registry)` возвращает redacted `AuthConfiguration`: trusted Key, stored policy snapshot и project encryption key для сборки. На ошибке возвращает пустой объект. `Codec.OpenAuth` выдаёт узкий `AuthKey`; его fmt/GoString/JSON скрывают значение. Строка ключа получается только явным getter trusted assembler, её нельзя писать в лог. Не утверждается гарантированное удаление Go strings из памяти.

DB loader и Auth loader используют общий `readRuntimeCredential` с прежним точным catalog SQL/reader profile. Auth loader проверяет encryption binding, читает policy в readonly RepeatableRead transaction под lease и runtime profile, затем вызывает current runtime batch probe для одного ключа. Это постоянное число SQL операций без N+1/full catalog scan. Регистрация workers, кеширование полного realm или дополнительный pool не добавлены. Для каждого запроса пользователя loader не предназначен: его потребитель — ограниченная cold assembly.

Нет optional SMTP/provider auto-seed и нет автоматического преобразования stored enabled flags в availableMethods. Проверка зависимостей/готовности, actual adapter construction и повторная сверка policy перед serving остаются самостоятельной частью следующей сборки. Этот read-only snapshot не авторизует оператора и не даёт public setup secret. Новых административных/публичных endpoints нет.

## Результат локальных проверок

Luna V1: task check и affected race PASS. V2: полный TestPrepareCommandSQL PASS без SKIP, включая loader/runtime/roles/onboarding/managed и parent secrets replay/wrong-root; targeted lint cmd/project-prepare PASS (0 issues). Manifest7 совпал до/после и перед коммитом, собственный PostgreSQL fixture удалён. [Evidence](../planning/history.md#результат-mp41a-project-auth-loader--25-октября-2026). Это не полная Auth assembly/public readiness/fleet приёмка.
