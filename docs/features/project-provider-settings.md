# Google и Telegram: настройки проекта

## MP5.1q: API

`GET /api/v1/admin/auth/settings/providers/{provider}` возвращает provider/version/clientId/clientSecretSet. `POST` обновляет существующую row по expectedVersion; provider — только google/telegram. Секрет, ciphertext, root keys и issuer subject не возвращаются. Переиспользуются existing ProviderHandler/DTO/error mapper, Providers service и SQL. Базовый контракт — [provider-settings](provider-settings.md).

В UUID manifest `providerSettings` default false и требует browser. Программный флаг — `ProjectProfileConfig.ProviderSettingsEnabled`. Он независим от включения Google/Telegram login: credentials можно подготовить при отключённом методе, но новые login adapters/redirects/issuer endpoints не появляются автоматически.

Readiness разделена на `provider_settings_read`/`provider_settings_write`: metadata читается без доступной MFA/Redis или дешифрования секрета. Update публикуется только с готовой MFA management configuration и project-scoped ciphers. Все запросы — current project session/NoRefresh/exact Origin, permission auth.settings.manage; SQL update дополнительно проверяет свежие password+MFA. Platform principal и ENV credentials не используются.

## Секреты, версии и ограничения

Для каждого проекта используются те же derivation purposes, что у его OIDC runtime: provider-google:v1/provider-telegram:v1 внутри project scope. Service шифрует явно переданный clientSecret до SQL; nil/пропуск сохраняет ciphertext. Unchanged clientId с omitted secret — no-op без увеличения версии/аудита. Явная ротация увеличивает version, сохраняя SQL audit без plaintext secret.

В транзакции проверяются actor, policy и ожидаемая версия, блокируются нужные строки. При включённом методе запрещены очистка credentials и смена clientId. Для смены clientId нужны явный secret, отключённый метод и отсутствие linked identities для соответствующего issuer. Случайная смена идентичности провайдера не становится объединением аккаунтов по email.

Ротация меняет provider revision: existing OIDC callbacks и завершение MFA/enrollment/recovery должны пройти прежние revision guards; старый proof не даёт новую сессию. Уже существующие SQL-сессии этой операцией не отзываются. Это сохранённые SQL/runtime гарантии, а не новый механизм SSO.

Project adapter берёт один runtime lease на операцию, общий timeout5s, service deadline3s и pre/post current-binding guards. Результат не возвращается при ошибке финального guard; ошибка после SQL commit не доказывает rollback. Перед повтором нужно сверить текущую version. Внутри lease нет внешних HTTP/OIDC запросов.

API обновляет подготовленные project provider rows; отсутствие row даёт existing GET403, не разрешает автоматически инициализировать из ENV или добавить bootstrap через update. Trusted project onboarding остаётся отдельным контрактом. Новых schema/deps/ENV/workers/cache нет.

## Проверки

Добавлены source/default-off/UUID isolation/prerequisite/route cases. Actual HTTPS project fixture проверяет оба провайдера: 401/403/Origin, unsupported provider400, secret-free read/update, ciphertext rotation, decryption тем же project scope, preservation/no-op/stale-version/audit, clientId change409, сохранение существующей OIDC session и missing-row/no-seed. Own provider rows/audit восстанавливаются без изменения policy.

Existing project identity callback-rotation case и targeted TestProviderSettingsSchema сохраняют покрытие stale provider/MFA proofs и concurrent rotation. Локальные проверки Luna PASS: task check/API/race, полный Linux ARM64 TestPrepareCommandSQL с project_provider_settings_HTTP без skip и targeted TestProviderSettingsSchema. Реальный внешний OAuth exchange, полная two-project matrix/securityreview/GC/RPS/UI остаются отдельными gates.
