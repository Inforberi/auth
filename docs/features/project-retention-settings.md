# Сроки хранения данных проекта

Проектный API использует существующие retention service, SQL и HTTP DTO. Новых миграций, зависимостей, переменных окружения и workers нет.

## Подключение и доступ

В project manifest включается `retentionSettings: true`; по умолчанию флаг выключен и требует `browser: true`. Программная настройка — `ProjectProfileConfig.RetentionSettingsEnabled`.

- `GET /api/v1/admin/auth/settings/retention` возвращает сохранённые `version` и `policy`.
- `POST /api/v1/admin/auth/settings/retention` принимает `expectedVersion`, полную `policy` и `confirmShortening`.

Обе ручки требуют текущую сессию проекта, точный разрешённый Origin и право `auth.settings.manage`. Используется NoRefresh: чтение и запись не продлевают сессию. Чтение доступно независимо от MFA; запись публикуется при готовой конфигурации управления MFA и сохраняет текущую SQL-проверку свежих password/MFA proofs. Изменение обязательности MFA — отдельный этап.

`retention_settings_read` и `retention_settings_write` имеют отдельную readiness. Запрос получает один lease к БД конкретного проекта, deadline 5 секунд и проверку актуальности binding до и после операции. Вложенный service ограничен 3 секундами. Пулов, кеша и сетевых вызовов внутри операции не добавляется. Ошибка финальной проверки после SQL commit не означает откат: перед повтором следует перечитать версию.

## Значение настроек

Политика содержит `emailReservationDays`, `sessionDays`, `securityAuditDays`, каждое поле — от 1 до 106751 дней. Смысл полей и bootstrap defaults описаны в [общем контракте retention](retention-settings.md). Сохранённая SQL-политика имеет приоритет над ENV; GET и POST не создают отсутствующую строку. Trusted onboarding остаётся отдельным процессом. Missing-row GET возвращает существующий 403.

Запись блокирует строку, проверяет актуальные права и `expectedVersion`. Устаревшая версия возвращает 409 `retention_settings_conflict`. Реальное изменение атомарно увеличивает версию и добавляет audit; no-op не меняет ни версию, ни audit. Уменьшение любого срока требует `confirmShortening: true`, иначе 409 `retention_confirmation_required`.

API не запускает очистку. Следующая партия существующего worker прочитает актуальную SQL-политику; уже запущенная партия может закончиться со старой в пределах своего deadline. Сокращение срока допускает последующее необратимое удаление данных. Сроки действующих сессий и временных challenges этой операцией не меняются. Размер партий, интервалы и общий бюджет worker остаются deployment-настройками.

## Проверки

Добавлены проверки default-off, независимости проектов, browser/MFA prerequisites и маршрутов. Реальный HTTPS fixture проверяет права, Origin, границы значений, no-op, конфликт версии, подтверждение сокращения, audit, отсутствие продления сессии и отсутствие ENV fallback. Он восстанавливает собственные настройки и не запускает очистку. Существующий `TestRetentionSettingsSchema` покрывает SQL constraints, конкуренцию, откат при ошибке audit и применение сохранённой политики worker.

Отдельная Luna проверила неизменяемый снимок: task check, API check, targeted race, полный Linux ARM64 TestPrepareCommandSQL с новым HTTPS subtest без пропусков и TestRetentionSettingsSchema — PASS. Все 11 исходников и deployment JSON совпали со снимком; временные стенды удалены. Общая двухпроектная приёмка, security review, GC/RPS и UI этим блоком не закрываются.
