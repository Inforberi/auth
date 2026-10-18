# Каталог независимых проектов — MP2.1 foundation

18 октября 2026. Реализована внутренняя read-модель каталога и отдельная SQL migration. Это не готовая платформа: текущий Auth runtime не переключён, операторы/management API/provisioning/admin bridge ещё не подключены. [ADR005](../adr/005-independent-projects.md), [порядок MP2–MP8](../planning/multi-project.md).

## Владельцы

- `internal/platform/project/domain`: идентификатор, slug/display name/canonical origin, desired state/phase и admission predicate. Нет новых внешних зависимостей.
- `internal/platform/project/repository/postgres`: внутреннее чтение/resolve/список, caller-owned pool. Не создаёт соединения на каждый запрос и не управляет lifecycle платформы.
- `migrations/platform/000001_catalog.{up,down}.sql`: отдельный набор для будущей платформенной БД, не изменение применённой Auth000001. Текущие migration команды/ENV не менялись; migration нигде не применена в этом блоке. Не запускать platform down на рабочей БД.

## Данные и состояния

Таблица `platform.projects`: UUID, immutable-public slug, display name, exact HTTPS origin, desired state, preparation phase, optimistic version/runtime generation, trusted storage target, optional database name/credential reference, schema version и timestamps. Credential reference — идентификатор будущего защищённого хранилища, не plaintext password или DSN. Secret encryption/provisioning реализуются отдельно.

| Поле | Значения | Значение для доступа |
| --- | --- | --- |
| desired_state | enabled / suspended | Приостановка не превращает существующую БД в заново создаваемую |
| phase | pending / provisioning / failed / ready | Готовность подготовки, не результат health probe |
| admission | enabled AND ready | Unknown/пустое состояние не допускается |

Новый ряд по умолчанию pending/enabled и не допускает запросы. Ready требует непустых storage binding/schema metadata. SQL constraints задают допустимые значения/целостность, но не заменяют actor/version/state-transition guards будущих mutating use cases. Изменения slug/origin/versions пока не опубликованы: правила immutable identity и переходов должны быть enforced в будущих операциях, не считаются уже реализованными только из-за read-модели.

Slug1–63 ASCII символа, starts-letter, без trailing hyphen и reserved admin/api/auth/console/platform/www. Display name — непустой UTF-8 до200bytes, без controls, trim выполняется в domain. Canonical origin — exact HTTPS DNS host с optional non-default port; без credentials/path/query/fragment/IP/uppercase/trailing dot. Syntax validation не доказывает владение доменом и не выбирает trusted auth-domain: регистрацию/binding проверит platform service.

## Внутренние операции

| Метод | Контракт |
| --- | --- |
| Read(ID) | Одна строка metadata по UUID; invalid ID отклоняется до SQL, unknown → ErrNotFound |
| Resolve(origin) | Один uncached exact lookup только enabled/ready; возвращает private Binding с target/database/credential-ref/schema version. Pending/failed/suspended/unknown/noncanonical → одинаковый ErrNotFound, без default project |
| List(query) | Limit1–100, optional phase, keyset `(created_at,id)` descending, limit+1 для next cursor. Без OFFSET/COUNT/N+1. Items содержат только Project metadata, не storage binding |

Каждый метод ограничен2s с учётом caller context; rows закрываются/Err проверяется. Connection/SQL/scan failure → ErrUnavailable без raw driver details, cancellation остаётся доступна через errors.Is. Resolve не является аутентификацией пользователя и не заменяет storage identity/generation/schema check будущего runtime registry. Caller обязан проверять error до использования результата.

Read/List не содержат platform authorization: это внутренние persistence операции, пока без service/HTTP wiring. Они не должны публиковаться напрямую до отдельной operator realm/current SQL authority. Binding не является публичной карточкой: будущие HTTP DTO явно исключают storage metadata/credential references. Reserved operator origin/host policy и односессионный admin bridge остаются будущими guards.

Индексы: unique ID/slug/origin; created_at/id для страницы и phase/created_at/id для фильтра. Схема/table не выдаёт privileges PUBLIC; реальные роли/grants создаются отдельно после operator authority. Числа пропускной способности не измерялись.

## Проверки и ограничения

- Gofmt, domain/repository unit tests и финальный `task check`: PASS/lint0. Unit cases: UUID/slug/name/origin bounds, closed-by-default state combinations, page/cursor bounds до SQL, no-row/unavailable mapping без secret leak и сохранение cancellation. Лог `/private/tmp/auth-platform-catalog-check-final.log`.
- Первый lint выявил complexity и форматирование, исправлено без отключения правил. Исходный task check log — `/private/tmp/auth-platform-catalog-check.log`.
- `migrations/platform/catalog_test.go` содержит opt-in PostgreSQL test для отдельной disposable `auth_platform_test`, user auth, localhost или `/var/run/postgresql`. Защита требует отсутствия schemas auth/platform перед migration; teardown удаляет только созданную platform schema. Проверяет up/down, ready binding constraints/unique origin, pending/failed/suspended/unknown denial, immediate uncached update, keyset ties/filter/empty page, selective indexes на2048 synthetic catalog rows, PUBLIC ACL и cancellation/pool release.
- **SQL integration NOT RUN.** Docker daemon недоступен; `docker inspect` не выполнился, команда CREATE DATABASE после `&&` не запускалась. Локальных postgres/initdb/psql не найдено. Test binary собран для Linux/arm64, но компиляция не проверяет SQL syntax/constraints/planner. В обычном task check integration test пропускается без `AUTH_PLATFORM_TEST_DATABASE_URL`; это не SQL PASS.
- Не запускались live/race/load/fleet/provider/security operator checks; для read foundation без concurrency owner достаточно штатного check, но это не закрывает SQL gate или MP2 целиком. Существующая Auth БД/Redis/ENV/containers не менялись, Docker не запускался автоматически.

Ближайшее: реальный SQL test на разрешённом изолированном PostgreSQL, затем MP2.3–MP2.7 — operator realm/first-run/permission guards и management API. SQL/runtime integration gate остаётся открытым, пустые service/transport заглушки не добавлены.
