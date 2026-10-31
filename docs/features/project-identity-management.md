# Управление Google и Telegram в проекте

MP5.1i, 26 октября 2026. Подключены существующие OIDC handlers/services к project HTTP. Локальные проверки Luna V1/V2 PASS; реальный внешний provider exchange, полный MP5 и UI остаются отдельными gates.

## Маршруты

Для выбранного готового Google/Telegram browser profile:

| Метод и путь | Результат |
| --- | --- |
| POST `/api/v1/auth/google/link` | 200, authorizationUrl и browser-bound Google flow cookie |
| DELETE `/api/v1/auth/google/link` | 204, отвязка Google и очистка session cookie |
| POST `/api/v1/auth/telegram/link` | 200, authorizationUrl и browser-bound Telegram flow cookie |
| DELETE `/api/v1/auth/telegram/link` | 204, отвязка Telegram и очистка session cookie |

Все четыре операции требуют действующей `__Host-session`, точного Origin проекта и `NoRefreshAuth`. User ID/session hash берутся из проверенного auth context. Provider issuer/callback/credentials определяет прежний доверенный source и выбранная проектная БД. Platform operator session не становится project proof. CORS и произвольные issuers/redirects не добавлены.

Завершение привязки использует уже существующий GET `/api/v1/auth/{provider}/callback`. Login/link различаются сохранённым purpose, не параметром запроса. Для link обязательны прежняя browser flow cookie и исходная SQL session. Single-use state, PKCE, nonce, provider revision и повторная SQL authority сохраняются. При `Linked=true` callback не создаёт и не заменяет login session; flow cookie очищается. Идентичность определяется по issuer+subject, email не объединяет аккаунты; чужая идентичность/второй другой subject того же provider дают conflict.

StartLink не прикрепляет внешний аккаунт само по себе. Для работы метода нужны сохранённые проектные provider credentials и готовый профиль. SQL-disabled/невыбранный/неисправный provider не публикует эти routes; отдельного offline/force unlink здесь нет.

## Текущая политика подтверждения

Сохраняется существующий консервативный контракт: и link, и unlink требуют подтверждённый постоянный пароль и свежий session-bound password proof. Временный/неактивированный пароль не подходит. Вход только через Google+Telegram или email OTP без постоянного пароля не становится достаточным основанием для этих операций. Это явное ограничение текущего backend, не обещание отвязки по любому альтернативному фактору.

Свежесть проверяется перед start и повторно в SQL commit. Действующая session также проходит прежние role/MFA ограничения; отдельное новое требование fresh MFA здесь не введено. Сроки сессии/доказательства MFA не продлеваются middleware.

При unlink необходимо сохранить пригодный парольный вход:

1. Проектный HTTP проверяет готовность password capability, чтобы известная ошибка конфигурации/verification не оставила пользователя без опубликованного резервного входа.
2. SQL под user/session locks проверяет verified permanent credential; `LockPublicPolicy FOR SHARE` удерживает актуальный `password_enabled=true` до commit. Наличие hash при выключенном способе больше не считается резервом.
3. Только после этого удаляются identity, повышается auth_version, отзываются все сессии пользователя и записывается audit одной транзакцией. При отказе identity, version и session сохраняются; ответ `409 last_login_method`.

Проверка runtime capability и транзакционная SQL authority имеют разные гарантии. Capability snapshot не обещает вечной доступности внешних зависимостей; отзыв/права не кешируются в профиле. Новая SQL-проверка применяется также к прежним standalone callers этого repository.

## Сборка и ресурсы

Новые management routes переиспользуют `ProjectOIDC.StartLink/Unlink/Callback`; собственного pool/worker/provider client нет. Shared owners, scoped Redis budgets/flow encryption, operation deadline, один UsePool и current key guards остаются прежними. Во время внешнего HTTP не удерживается physical SQL connection.

POST и DELETE одного link URL имеют разные handlers: при связывании HTTP сначала выбирается ключ `METHOD path`, затем прежний path-only binding для сценариев с общим handler. Allowlist и конкретный HTTP method по-прежнему задаёт RoutePlan/leaf router; method-specific binding не становится fallback выбора проекта или авторизации.

Новых ENV, flags, зависимостей, schema и миграций нет. Включение использует существующие manifest/provider/SQL настройки.

## Проверки

Добавлены route/protection/readiness guards и SQL regression для выключенного password fallback с сохранением identity/version/session. Existing project OIDC drill расширен реальным HTTPS для обоих providers: no-Origin/foreign-Origin/no-session, stale password proof, link flow cookie/callback URL, provider revision reject до exchange/replay/no new session, stale-policy rebuild, отказ unlink при выключенном password и успешный unlink/revoke/version increment после восстановления.

Fixture использует собственных пользователей и canonical cookie tokens, shared owners существующего drill и точные scoped Redis keys; policy/users/audit/sessions восстанавливаются/очищаются. Успешный внешний callback этим fixture не симулируется: существующие service/identity tests сохраняются, реальные Google/Telegram credentials отсутствуют.

Main formatter/source/read-only review. Luna V1: task check/API/security/affected race и Linux ARM64 `TestPostgresSchema/identity_management` со всеми nested SQL cases PASS. Исправлен только synthetic session INSERT: добавлены обязательные user_agent/ip_address. Luna V2: targeted lint/полный TestPrepareCommandSQL PASS, новый project_identity_HTTP выполнен без skips. Все 10 source hashes совпали после прогона и с main; собственные контейнеры/network/build files очищены. Snapshot/evidence — в history. Полная two-project матрица и MFA management остаются следующими задачами.

31 октября: Двухпроектный actual Google/Telegram link callback/unlink принят в TestTwoProjectIdentityManagementIsolationSQL: source session/pending scopes, freshness recheck, отсутствие новой session на link и A-only revoke на unlink. Luna V1 Go tests/actual SQL race и V2 targeted lint PASS, cleanup/manifest11 подтверждены; [scope и ограничения](../planning/multi-project.md#пользователи-и-привязки-двух-проектов--mp5-directory-identity-http). Production/shared helpers/schema/ENV/deps прежние, реальные provider/browser gates отдельно.
