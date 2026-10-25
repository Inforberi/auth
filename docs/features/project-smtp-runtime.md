# Проектный SMTP runtime

MP4.1d, 25 октября2026. Решение зафиксировано до реализации; код добавлен, локальные проверки Luna PASS.

- Потребитель — следующие проектные email/outbox services; использовать существующие SMTP settings service и mailer, не дублировать SMTP/TLS/криптографию.
- Project key/current reader и scoped data key берутся из MP4.1a. SMTP config/password — только сохранённая запись той же project DB; никакого Initialize/ENV fallback/наследования SMTP платформы.
- Trusted deployment allowlist SMTP targets и строгий TLS проверяются до сети. Настройки проекта сами по себе не разрешают произвольный egress. Изменяемый caller slice не должен менять ограничения после сборки.
- Credentials читать под existing pool-entry lease с current catalog guard до/после и existing registry connection/profile guards. Не сохранять repo/service/pool за callback; вернуть только необходимую конфигурацию mailer. Во время SMTP dial/send SQL connection/transaction не удерживать.
- Текущие настройки перечитываются при отправке, чтобы смена SMTP не требовала hidden долгого credential cache. Учесть version/epoch проверки, deadline/cancellation и безопасные ошибки; не логировать password/ciphertext.
- Password/TOTP профиль не обязан иметь SMTP. Отсутствие записи не создаёт defaults или побочные записи; выбранная email-функция должна получить явный отказ до отправки, если доставка не настроена.
- Никаких новых deps/schema/public routes/публикации readiness. SMTP probe/management APIs и bounded outbox scheduling — отдельные следующие блоки, реальная внешняя доставка не объявляется проверенной по наличию config row.
- Тесты: project-only decryption/refresh, no-init/no-fallback, missing/corrupt/forbidden/plaintextTLS rejection, current target/suspend, borrowed resources и scoped cleanup. Реальные данные/ENV не трогать. Проверки — отдельная Luna на immutable snapshot, локальный Helmholtz только исследует.

## Реализация

`internal/app/auth/project_smtp.go`: `NewProjectMailer(ctx, key, allowedTargets, dependencies)` возвращает existing `mailer.Mailer`. Shared registry/reader/Redis принадлежат процессу; factory не закрывает их и не создаёт pool/worker. Allowlist копируется при сборке. Конструктор проверяет сохранённые credentials без сети; `ErrNotInitialized` означает, что выбранный email consumer пока нельзя собрать. Password/TOTP собираются независимо.

Каждый SendContext заново читает/расшифровывает запись через existing SMTP service под UsePool и трёхсекундным deadline. За callback выходит только mailer.Config, не repository/service/pool. Existing mailer ограничивает общую отправку20s, dial5s, проверяет STARTTLS и сертификат сервера до AUTH/письма. Данные читаются без Initialize, кеширования пароля или management probe. Scoped Redis limiter передаётся существующему service; чтение credentials не расходует лимиты административной SMTP-проверки.

Catalog guard не отзывает уже начатый внешний SMTP side effect: suspend после финальной проверки может совпасть с in-flight отправкой. Следующее чтение отклоняет stale key. DNS/IP egress ограничения задаёт также deployment; hostname allowlist не заменяет сетевую политику и не доказывает защиту от DNS rebinding сама по себе.

## Проверки

Добавлен `projectSMTPDrill` в `TestPrepareCommandSQL`: отдельная disposable project DB, scoped encrypted settings, missing/no-init, unchanged xmin, caller allowlist isolation, reread запретного target/TLS/corrupt/deleted settings, suspend и отсутствие расхода probe-limit keys. Сервер намеренно не предлагает STARTTLS: проверяется отказ до AUTH/recipient/body и свободное единственное SQL-соединение во время сети, не успешная TLS-доставка.

Formatter/diff выполнены. Отдельная Luna: `task check` exit0/lint0 после разрешения loopback sockets; targeted race app/auth+cmd exit0; actual full TestPrepareCommandSQL exit0 без SKIP на PostgreSQL18.6 TLS/SCRAM+Redis8.2DB15. Manifest3 совпал до/после и с main; owned cleanup подтверждён. Первый sandbox task check exit201 был отказом bind, source не менялся. Внешний SMTP delivery, public routes, email/outbox consumers, fleet budgets и readiness остаются открыты.
