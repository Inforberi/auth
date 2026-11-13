# Текущий шаг

13 ноября 2026. В [плане управляемой установки](../planning/ui-management.md#12-установка-и-управляемая-смена-секретов-без-ручного-env) по запросу пользователя закреплены установка без ручного ENV, генерация/защищённое хранение внутренних secrets, безопасная смена root/signing keys и managed DB credentials через UI/API, независимый recovery при неработающей панели. Обновлены U1/U5/U7 и UI-спецификация. ENV-режим сохранён отдельно.

Управление включает lifecycle metadata/status, права, preflight/version guards, durable этапы/retry, проверку подключения, переход consumers/pools, cleanup старых credentials и audit. Privileged executor отдельно от Auth runtime; внешние БД требуют полномочий; нет обещания ACID/zero-downtime password rotation. Root keys вне зависимой БД; backup compatibility/re-encryption/JWT distrust и восстановление без публичного setup bypass обязательны. Новые store/installer/dependencies ещё не выбраны.

Только документация. Код/установщик/API/UI/ротации не реализованы, проверки приложения не запускались, коммит не запрошен. Следующий шаг — согласование конкретных контрактов U1, без автоматического старта реализации. [Итог локальной приёмки](../operations/operational-security-2026-11-13.md#итоговый-отчёт--безопасность-и-эксплуатация) не означает готовность нового функционала или полного production disaster recovery.

Все executable checks только Luna 01a16eab-c777-78a0-a815-47b45ff0860d; реальные env/keys/data/deploy/restore не разрешены. Сохранять user edits/staging.

Дополнение: [README и примеры](../planning/ui-management.md#13-короткий-readme-установка-и-примеры) включены в план/U7. Короткая точка входа: два режима, требования/quick start, реальный Auth пример, навигация к ENV/API/CRM/sandbox/update/backup/recovery; без копирования полного справочника или описания planned как реализованного. README обновлять в том же рабочем блоке при изменении пользовательского поведения/установки/контрактов; внутренние изменения не требуют формального переписывания. Сейчас сам README не менялся, код и новые проверки не запускались.
