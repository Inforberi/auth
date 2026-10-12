# Документация Auth

- [Подробное руководство по Auth](auth-guide.md) — подключение, все текущие HTTP-методы с примерами, сценарии входа и восстановления, ENV, ограничения и отдельно будущие возможности.
- [Архитектура](architecture.md), [схема](schema.md) и [модель угроз](threat-model.md) — решения и границы проекта.
- [API-контракт](api/contract.md) — текущее поведение ручек. `api/generated/` содержит только generated Swagger; источник — DTO/аннотации в коде. Генерация: `task swagger`, проверка drift: `task check:api`.
- [Фичи](features/) — verification, recovery, смена email и удаление аккаунта.
- [Вход по email-коду](features/email-otp.md) — отдельный optional login без пароля, не verification/MFA.
- [MFA: TOTP и резервные коды](features/mfa.md) — внутренняя основа A5.1; публичный challenge/HTTP ещё не подключён.
- [Вход через Google](features/google-login.md) — optional OIDC login/link/unlink, настройки и ограничения.
- [Роли и permissions](features/roles-permissions.md) — внутренние роли/назначения, актуальные права, delegation и ограничения до MFA/admin API.
- [Каталог доступов](features/access-catalog.md) — JSON permissions/шаблоны, ручной preview и безопасная загрузка при запуске.
- [Политика паролей](operations/password-security.md) — проверка пароля, Argon2, безопасный rehash и ограничения.
- [Roadmap](planning/roadmap.md) — согласованные этапы и scope; [implementation](planning/implementation.md) — конкретные задачи и статусы; [history](planning/history.md) — прошлые результаты проверок, не инструкция следующего шага.
- [ADR](adr/) — причины архитектурных решений; [template-adoption](template-adoption.md) — происхождение инфраструктуры.
- [Навигация для AI](ai/index.md) и [текущий шаг](ai/current-task.md) — компактные указатели на первоисточники, не копия документации.

Документы описывают в том числе будущие возможности. Поддержку функции подтверждают её статус, код и проверки; наличие пункта в плане не означает реализацию.
