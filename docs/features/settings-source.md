# Источник настроек — U2 foundation

14 ноября 2026. Первый блок принят по целевым проверкам Luna. Это foundation, не весь U2, не установщик и не UI. [Контракт U1](../planning/ui-u1-contracts.md).

## Режимы и существующая установка

`AUTH_SETTINGS_MODE=api` — default, сохраняющий текущее поведение: Auth policy, SMTP, Google/Telegram credentials, retention берутся из сохранённых строк; ENV только seed новой установки. Старые данные не перезаписываются новым startup. Владельцы и guards этих фич не меняются.

`AUTH_SETTINGS_MODE=env` — явный источник для тех же четырёх групп в основном realm. Policy материализуется в SQL до открытия трафика: текущие SQL authority/version/constraints по-прежнему действуют. Новые поля `AUTH_PASSWORD_ENABLED`, `AUTH_REGISTRATION_ENABLED`, `AUTH_PASSWORD_EMAIL_VERIFICATION` задают раньше фиксированные части policy; dev defaults true/true/optional сохранены для совместимости. Имеющиеся switches Google/Telegram/email OTP/JWT и их credentials берутся из startup input. Это не генерация секретов.

Settings mutations, включая MFA policy/каналы/Telegram settings, в ENV read-only; пользователи, личные факторы и назначения ролей — рабочие данные, не блокируются этим режимом. Проверка текущих полномочий предшествует отказу `409 settings_source_read_only`. Read и допустимые read-only diagnostics, например проверка сохранённого SMTP, остаются защищёнными и доступными. Полная ENV-настройка всех MFA/новых timings и прочих отсутствующих полей относится к следующим feature-блокам U2, не добавляется неявными переменными сейчас.

В platform deployment режим принадлежит установке. Проектные HTTP settings и platform policy bridge наследуют read-only ограничение через доверенный server context, а не пользовательский заголовок. ENV платформы не перезаписывает SMTP, ключи и policy всех project DB: подготовленные проектные профили/manifest сохраняют свой binding и existing SQL state. Проекция дополнительных per-project ENV inputs — следующий контракт feature policy, не копирование глобальных значений в соседние БД.

## Фиксация источника, перезапуск и конфликт

`auth.settings_source` хранит mode, initialized marker, generation и keyed fingerprints. Сырые secrets и открытые hashes паролей туда не записываются; HMAC использует имеющийся encryption root, новые ключи не генерируются. Отпечатки относятся только к перечисленным SQL settings groups, не ко всем deployment limits/TTL установки. Они не публикуются в HTTP.

API-bootstrap фиксирует прежний API ownership без reseed существующих настроек. ENV на уже созданной старой policy/initialized setup не включается неявно: требуется отдельная adoption-процедура. После фиксации источника изменение `AUTH_SETTINGS_MODE` отклоняет запуск. Команда перехода ENV ↔ API не входит в foundation; план миграции зафиксирован в U1.

Новый ENV-профиль и его encrypted settings публикуются одной транзакцией с generation/audit. Те же входы не меняют versions/audit; смена только retention не ротирует provider/SMTP secrets и не сбрасывает counters. Сохранённые обязательные строки нельзя удалить и восстановить defaults при restart. Ошибка в любой группе откатывает весь startup sync.

Суммарно **один слот существующего основного pool** зарезервирован на экземпляр для advisory shared fence источника; новых pools/workers/брокеров нет. `MAX_CONNS>=2`, остальные подключения остаются в существующем budget. Обычный Auth request не читает source table; mode metadata читается только в административном settings read, writable source проверяется внутри уже существующей mutation transaction.

Одинаковый ENV профиль может обслуживаться несколькими экземплярами. Для нового fingerprint требуется exclusive fence: пока хотя бы один прежний экземпляр держит source lease, запуск с отличающимся input отклоняется. Менять ENV профиль нужно в maintenance окне с остановкой прежних экземпляров, а не mixed rolling update. При закрытии/ошибке сборки физическая fence connection закрывается; readiness проверяет её доступность.

Сокращение retention требует явного `AUTH_ENV_CONFIRM_RETENTION_SHORTENING=true`; это не отключение policy validators. Provider client ID с существующими привязками не меняется startup sync; ограничения последнего пригодного администратора сохраняются при ужесточении policy. Неподготовленный метод или неверный ключ не получает fallback. Отдельная keyed root binding запрещает заменить encryption root обычным ENV restart: до U5 это конфликт источника, а не частичная перезапись SMTP/providers новым ключом при оставшихся старых MFA/outbox данных.

## API metadata

Existing `GET /api/v1/admin/auth/settings` дополнен безопасным `source`:

```json
{"mode":"env","readOnly":true}
```

Поле вложено в прежний settings response. Остальные версии, policy/readiness/token metadata сохраняются. Platform/project settings view переносит inherited source в то же DTO. Actor-only checks, no-store и отсутствие implicit session refresh сохранены. Новых management routes нет.

## Схема и upgrade

Добавлена настоящая incremental Auth migration **000002_settings_source**: control row и redacted audit с retention index. Это новая schema capability, не переписывание существующих данных 000001. Fresh embedded Auth schema/version включает обе миграции, `AuthVersion=2`; обычный migrate up применяет новый файл. Worker удаляет source audit тем же bounded security-retention механизмом.

Для существующей standalone/API установки: сохранить backups/keys, остановить старых writers, применить 000002 и согласованные runtime grants, запустить текущий бинарник с API mode. Нельзя применять миграции/restore к рабочей БД ради теста. Старый schema или отсутствующая control row не считаются новой установкой.

Managed projects проверяют schema version/checksum/binding по-прежнему строго: существующий v1 проект нельзя объявить v2 одной правкой каталога. Нужен согласованный owner-side upgrade schema/grants/identity и новая проверенная binding/generation перед публикацией. Автоматический project upgrade executor будет частью installation/preparation блока; foundation не запускает DDL из request runtime. Пока upgrade не выполнен, несовместимый профиль остаётся закрыт, его данные не удаляются.

Rollback 000002 отклоняется для зафиксированного ENV режима: удаление таблицы не должно молча снять read-only защиту. API adoption/вывод старых binaries требует той же отдельной maintenance-процедуры, не reset.

## Передача на проверку

Необходимы: targeted config/source/unit/HTTP mapper tests; новый source SQL round-trip (ENV seed, same-profile replica/no-op, live-profile conflict, maintenance resync, audit/rollback, readonly authority и metadata, API legacy adoption/no reseed); affected Auth/MFA/settings compatibility; source/context на platform/project settings и актуальный schema/grants путь. Только собственные disposable fixtures; прежние crypto/TLS/login/load/scanners не повторять. Luna подтвердила сборку, Swagger, прямой upgrade и семь SQL-сценариев без пропусков. После финальных правок два затронутых SQL-сценария повторно прошли, целевой линтер — 0 замечаний. Снимок 334e0ed22bb118b6d8f04ff33451959c86f74b0c2679e781b4edc6eb13ff69d3, отчёт /private/tmp/auth-u2-final-e8Qjlg/summary.json.
