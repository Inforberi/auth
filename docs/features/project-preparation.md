# Резервация подготовки проекта — MP3 foundation

19 октября 2026. Этот документ описывает **внутренний catalog port подготовки**, отдельно от physical storage stage. `PreparationRepository.Reserve` атомарно сохраняет резервацию ресурсов, переводит pending → provisioning и записывает существующий lifecycle audit. Из HTTP/worker он не запускается; ручной executor добавлен в [следующем MP3-storage блоке](project-storage-preparation.md). Auth API не получает его credential. [Creation API](platform-project-creation.md), [lifecycle](project-lifecycle.md), [план MP3](../planning/multi-project.md#mp3-создание-бд-и-подготовка-проекта).

## Данные и границы

`platform.project_preparations` хранит одну запись на project UUID: неизменяемый random reservation UUID, target, createdAt и последнюю begin operation/version/generation. Она пока доказывает только сохранённое намерение/идентичность резервации, **не наличие и не принадлежность БД/роли**. Резервация не является lease или правом на внешний DDL.

Технические имена вычисляются из **неизменяемого project UUID**, а не display name/slug: `authp_<32 hex>` для БД и `autho_<32 hex>` для роли. Разные пространства имён, длина38bytes, без клиентской интерполяции SQL. Смена reservation UUID не должна направлять исполнителя на вторую БД с новым именем; сама смена UUID штатным retry запрещена. Перед будущим DDL необходима независимая проверка realm/project/reservation marker и реального owner/OID: совпадение имени не разрешает adoption.

Nonce/target/проект/createdAt не обновляются при повторе или новом begin после явного retry. Только operation/version/generation меняются при действительно принятой новой попытке. PUBLIC grants отсутствуют, HTTP DTO эти metadata не раскрывают. Резервации не очищаются: это ownership state, не расходуемый receipt с автоматически применяемым Auth180d retention.

## Транзакция и повторы

Вызывающий trusted компонент передаёт project/operation UUID и ожидаемые version/generation. Realm и единственный target берутся из доверенной конфигурации конструктора; Principal/actor из HTTP здесь нет. Actor audit — provisioner с UUID проверенного platform realm, не выдуманный проектный пользователь.

1. Проверяется отдельный минимальный catalog SQL profile и exact initialized realm.
2. Read Committed transaction берёт shared realm marker lock, затем вызывает прежний `Transition(begin_preparation)` с ожидаемой revision; project row остаётся locked до commit.
3. Проверяется текущая phase/version/generation, совпадение target и отсутствие прежнего database/credential/schema binding.
4. Точный replay возвращает прежнюю резервацию **без UPDATE** только пока begin receipt соответствует текущему epoch. После suspend/resume/другого изменения stale caller получает conflict, а не автоматически подставленную новую версию.
5. При первом begin генерируется reservation UUID. Он, lifecycle change и audit коммитятся вместе. При ошибке резервации откатываются также phase/version/generation/audit.

Повтор после потери ответа использует тот же operation UUID/expected revisions. Для failed проекта сначала нужен явный operator retry, затем новый begin с новым operation UUID и текущими revisions; это не автоматический бесконечный retry. Исторический begin receipt не выдаётся за полномочие продолжать более новый epoch.

Если резервация исчезла, но begin уже был принят, восстановление fail-closed: ни старый replay, ни новый retry не генерируют замену nonce. Поиск предыдущих begin ограничен project_id и поддержан partial index `project_preparation_history`, без обхода всех проектов. Это касается и частично утраченного metadata после сбоя/restore; потеря **всего** соответствующего history вместе с резервацией не доказывается этим guard и потребует будущих storage markers/restore protocol. Нельзя очищать begin history независимо от ownership records.

Все обращения ограничены общим3s, rollback cleanup имеет отдельный1s context. Независимые проекты не блокируются глобальным preparation mutex. Пул принадлежит вызывающему компоненту; отдельный pool/client на проект, goroutines или очередь этот port не создаёт. Он ещё не реализует fleet concurrency budget, внешний lease/fencing или безопасную параллельность DDL разных процессов.

## Credential и grants

[Отдельный template](../../deploy/postgres/grants/platform-preparation-grants.sql) рассчитан на catalog LOGIN `auth_platform_preparation` в платформенной БД. Его создаёт оператор отдельно; runtime owner/superuser/CREATEDB/CREATEROLE не подходит. Права: platform metadata SELECT, минимальные lifecycle/event column grants и preparation INSERT/UPDATE только mutable attempt fields. Нет Auth schema USAGE, operator grants mutation, project INSERT/DELETE/binding rewrite, event rewrite или preparation DELETE/identity rewrite.

Для shared row lock realm PostgreSQL требует UPDATE хотя бы одной колонки: разрешена только `singleton`, CHECK допускает только TRUE. UUID/initializedAt/firstOperator изменять нельзя. Это не разрешение сбрасывать setup. `CheckRuntime` проверяет допустимые/недостающие права; каждый Reserve вновь проверяет profile и блокирует matching initialized marker в транзакции. Auth operator startup отдельно отвергает даже column-only preparation DML, чтобы обычный API не использовал этот credential.

SQL grants не ограничивают trusted SQL writer одной предметной командой: матрицу/actor/fences обеспечивает этот port. Он не публикуется как прямой HTTP доступ к SQL. Будущий storage credential с DDL будет отдельным от catalog credential; настоящие пароли/DSN/ENV этим блоком не добавлялись и не читались.

Таблица и partial index добавлены в **исходную** catalog000001, без новой migration. Down удаляет preparations до projects. Existing install требует controlled forward upgrade, не reset/replay initial migration; рабочая Auth БД не менялась.

## Проверки и следующий блок

Domain tests проверяют UUID/имена/стабильность при смене nonce. Live PostgreSQL18.6/Redis8.2.6/local TLS regression использует настоящий отдельный ограниченный preparation LOGIN: API/owner credentials отвергаются, excess realm/nonce/Auth grants отвергаются, чужой target откатывает begin,4 concurrent replays дают одну резервацию/один begin без UPDATE, заблокированный project имеет bounded cancellation и не мешает другому. Ошибка reservation INSERT откатывает весь begin/audit; stale epoch отвергается; явный failed→retry→begin сохраняет nonce/createdAt; утраченный ownership record не восстанавливается новым nonce даже после нового retry.

Результаты/cleanup/NOT RUN — [history](../planning/history.md#результат-mp3-reservation-foundation--19-октября-2026). Обычный race без opt-in ENV не является live SQL-race. Не проверены реальные physical databases/target credentials/процесс executor/DNS/TLS onboarding/fleet/load/GC; storage готовым не объявляется.

Следующий physical подблок выполнен отдельно: [MP3-storage](project-storage-preparation.md) добавил single trusted target, one-shot executor, durable target ownership ledger, actual owner/database OID checks и session serialization. Здесь описаны только catalog foundation guarantees. Дальше — schema/grants/независимые ключи/admin setup/readiness и scheduler. Не публиковать ready, запускать DDL из HTTP или принимать существующую БД по одному имени. UI не начинался.
