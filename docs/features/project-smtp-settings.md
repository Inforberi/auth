# SMTP settings API независимого проекта

## MP5.1p: маршруты и выбор возможности

| Метод и путь | Действие |
| --- | --- |
| GET `/api/v1/admin/auth/settings/smtp` | Прочитать configuration/version/passwordSet без пароля |
| POST `/api/v1/admin/auth/settings/smtp` | Заменить configuration и при необходимости пароль |
| POST `/api/v1/admin/auth/settings/smtp/test` | Проверить сохранённую версию соединения, не отправляя письмо |

Переиспользуются existing SMTPHandler/DTO/mapper, settings.SMTP validation/crypto/budgets и SQL authorization/version/audit. Базовый контракт — [smtp-settings](smtp-settings.md). Actor только из текущей project session, permission `auth.settings.manage`. NoRefresh/exact browser Origin/no-store; update/test требуют свежие password+MFA в SQL, GET — без свежих proofs.

В UUID manifest `smtpSettings` default false и требует browser. В программной сборке — optional `ProjectProfileConfig.SMTPSettings{AllowedTargets}`. Readiness `smtp_settings_read` отделена от `smtp_settings_write`: metadata можно прочитать без доступного Redis/MFA/SMTP; update/test требуют готовую MFA management configuration, Redis и валидный target allowlist. Capability не зависит от работающего delivery worker и не проверяет соединение при сборке.

Доверенный allowlist берётся из existing deployment `PLATFORM_PROJECT_DELIVERY_SMTP_ALLOWED_TARGETS`; он не передаётся в JSON административного запроса и не наследует platform SMTP secrets. Source копирует список, legacy deployment без manifest не включает новые endpoints. Пустой/невалидный список закрывает write/test. Допускаются только точные host:port из списка, без wildcard; TLS обязателен. Проектный encryption purpose `smtp-settings:v1` и Redis namespace совпадают с его существующим delivery runtime, другие проекты не используют эти credentials.

## Обновление и отсутствие автоматического bootstrap

`expectedVersion` защищает от потери изменений; plaintext password шифруется до SQL записи. Отсутствующий/null password сохраняет существующий, смена host/port/username требует явного нового пароля. Отключение TLS и адрес вне allowlist отклоняются до соединения. No-op не меняет version и аудит; секрет не возвращается ни в одном ответе.

API изменяет уже подготовленную SMTP row проекта. При отсутствии row GET сохраняет existing `403 forbidden`, не отличая этот случай от отказа в доступе; это не разрешение читать ENV или инициализировать настройки при GET. Trusted project onboarding/initialization остаётся прежним отдельным контрактом; новые seed/bootstrap endpoints не добавляются.

## Сетевой тест и ресурсы

Сервис SMTP сохраняется в resident profile, но его repository adapter берёт runtime lease только на отдельную SQL операцию с timeout5s и pre/post current-binding guards. `AuthorizeSMTPTest` завершает authorization transaction и отдаёт encrypted snapshot до возврата lease. Затем существующий service применяет scoped budgets, decrypt/allowlist/TLS validation и выполняет probe без удержания pool lease/SQL locks. Probe проверяет актуальность project binding до соединения и после успешного завершения.

Probe ограничен10s и existing Redis limits3/user/min,10/project/min. Один shared SMTPTestGate у ProjectHTTP owner ограничивает2 одновременных project probes, включая старые/пересозданные profiles и разные проекты. Пересборка profile не сбрасывает semaphore. Для direct BuildProjectProfile caller может передать общий gate через ProjectProfileDependencies.SMTPTests; без него isolated build владеет своим gate. Standalone NewSMTP сохраняет прежний собственный gate.

Тест проверяет greeting/STARTTLS/AUTH/NOOP сохранённой авторизованной версии, а не доставку письма и не будущую доступность сервера. Смена/отзыв конфигурации после admission не превращает результат в новую readiness-гарантию. Ошибка после изменения SQL/последнего binding guard не доказывает rollback; перед повтором нужно перечитать settings.

Новых таблиц, миграций, сторонних зависимостей, ENV, workers и кеша credentials нет.

## Проверки

Добавлены source/default-off/UUID isolation/allowlist-copy и prerequisite/route tests. Behavior test shared gate удерживает два probes в разных service instances, отклоняет replacement и разрешает после освобождения. Actual HTTPS/SQL fixture проверяет права/Origin, read без secrets, encryption/rotation/preservation, TLS/allowlist denial, expectedVersion/no-op/audit, 429 и отсутствие автоматического seed при пропавшей row. Во время controlled network probe проверяются доступность registry pool и `FOR UPDATE NOWAIT`; fake server без STARTTLS получает409 до AUTH/письма. Свои settings/audit/точные Redis keys восстанавливаются.

Локальные проверки Luna PASS: task check/API, targeted race и полный Linux ARM64 TestPrepareCommandSQL с project_SMTP_settings_HTTP без skip. Успешная проверка реального внешнего SMTP/доставки, full two-project matrix, securityreview/GC/RPS/UI остаются отдельными gates; отрицательный STARTTLS fixture их не закрывает.
