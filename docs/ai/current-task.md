# Текущий шаг

3 ноября 2026. R5 завершён и принят Luna: снимок `/private/tmp/auth-r5-account-password-v4-_34822o1`, base cfa0421. R5 включён в коммит `refactor(auth): разделил account и парольные сценарии`; актуальный hash и staging проверять Git. Сохранены прежние четыре Markdown изменения процесса проверок.

Account/email, provisioning, setup и password/recovery, provisioning получили собственные service/HTTP/tests. Общие domain/ports/admission, SQL transaction owners и API-контракты сохранены. Provisioning/EmailChange/Activation получают технические зависимости явно; приватные детали не открывались ради tests. Архитектура и пути обновлены.

Luna PASS: 35 affected Go packages под race, pinned lint0, API reproduction, 8 exact SQL roots actual RUN/PASS/exit0 без SKIP/NOT RUN. Main сверил source hashes и actual SQL logs. Evidence/fixture/ограничения — [acceptance-summary](../operations/acceptance-summary.md#r5-account-и-методы-входа--приёмка-3-ноября-2026).

Следующий блок: [R6](../planning/readability-refactor.md#r6-сессии-jwt-роли-и-настройки) — session/token/access/settings/audit/delivery по подтверждённым проблемам; уже связное не переписывать. Перед реализацией определить достаточный affected scope. Коммит только по разрешению пользователя.

Все executable checks и стенд — отдельный чат Luna 01a16eab-c777-78a0-a815-47b45ff0860d; main пишет/исправляет/форматирует. Собственный стенд `auth-r5-retained` сохранён по указанию пользователя, данные очищены; metadata `/private/tmp/auth-r5-retained-fixture.json`, Compose `/private/tmp/auth-r5-retained-compose.yml`. Перед следующим прогоном Luna сверяет совместимость и использует актуальную сборку; чужие ресурсы не трогает. Обязательный tool report Luna→main 01a1084e-24bd-79f3-8c3a-769ffd8ec98a. R2 live/external/MP7/MP8 gates отдельно; UI без согласования не начинать.
