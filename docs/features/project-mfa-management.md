# Управление MFA проекта

MP5.1j, 26 октября 2026. Реализована HTTP-проводка существующего MFA management, локальные проверки Luna V1/V2 PASS. Это не новый MFA protocol, не recovery при потере всех факторов и не начало UI.

## API

Пути ниже находятся под `/api/v1/auth` на точном HTTPS origin проекта. Все восемь routes используют project `NoRefreshAuth`; изменение требует exact Origin, чужой Origin отклоняется, CORS не включён. Proof формируется из проверенной session: user ID, token hash и auth_version, без соответствующих полей из JSON.

| Метод и путь | Результат |
| --- | --- |
| GET `/mfa/status` | Состояние TOTP, требования роли/административных прав, допустимость отключения по политике, число recovery codes, наличие свежих proofs; без секретов и refresh |
| POST `/mfa/totp/enrollment` | Новый token/secret/URI/expiry в no-store owner response; фактор ещё не включён |
| POST `/mfa/totp/enrollment/confirm` | JSON token/code; проверка нового TOTP, десять recovery codes один раз, отзыв сессий |
| POST `/mfa/step-up` | JSON code/recovery; одноразовая проверка фактора, свежий MFA proof и замена текущей cookie без продления сроков |
| DELETE `/mfa/totp` | Отключение, только если текущая SQL policy разрешает; удаление recovery codes и отзыв сессий |
| POST `/mfa/recovery-codes/regenerate` | Десять новых codes один раз, прежние digests заменяются, сессии/переходные challenges отзываются; TOTP сохраняется |
| POST `/mfa/totp/replacement` | Pending новый TOTP secret/token; старый фактор остаётся активным до подтверждения |
| POST `/mfa/totp/replacement/confirm` | JSON token/code нового фактора; атомарная замена TOTP/recovery codes и отзыв сессий |

Status не требует свежего primary proof, но требует действующую актуальную owner session. Его policy flags информационные: каждая mutation проверяет условия заново. Enrollment требует свежего primary proof; replacement, disable и recovery rotation — также свежего MFA proof. Срок свежести management SQL — прежние пять минут, без client timestamps.

Обычный MFA login сохраняет primary/MFA context, но не выдаёт отдельный sensitive-operation password proof. Для password аккаунта после него нужен существующий `POST /reauthenticate/password`; успешный ответ меняет cookie, сохраняя MFA context. Эту cookie следует использовать для management. Специальный административный login intent имеет собственный прежний контракт proof.

Primary proof — password либо существующий opt-in email reauthentication для external-only аккаунта. Последний включается только при готовой выбранной email reauthentication capability; SQL дополнительно требует verified email, совпадающий с proof, linked identity и отсутствие password/temporary credentials/незавершённой активации. Это не объединение аккаунтов по email и не обход пароля владельца password account.

Pending enrollment привязан к user/session/auth_version/purpose; проверяются срок, лимит ошибок и одноразовое применение. TOTP/recovery проверяют прежние primitives, raw secret/codes не сохраняются в логах. Enrollment/replacement/disable/rotation повышают auth_version и отзывают доступ транзакционно с audit. Они не создают сессию: после успеха нужен обычный login и, пока TOTP включён, второй фактор. Step-up заменяет только verifier и MFA proof текущей сессии, без изменения сроков и primary proof.

## Политика и доступность

Существующий SQL запрет отключения обязательной MFA по роли/административным полномочиям сохранён; HTTP не может его отменить. У обычного пользователя без такого требования MFA остаётся добровольной. Этот блок не вводит новые project-wide required/optional settings и не ослабляет существующие административные требования; согласованные настройки режимов и UI рассматриваются отдельно.

MFA configuration/session policy всех сконфигурированных browser methods должны совпадать. При disabled browser/MFA routes отсутствуют; неготовый Redis/невалидный config/inconsistent policy закрывает management. `MFA.Enabled` означает наличие поддерживаемой реализации, а не автоматическое требование второго фактора каждому пользователю. Регистрация фактора не разрешается при несогласованной конфигурации разных browser methods.

Management собирается независимо от SQL включённости primary methods: уже аутентифицированный пользователь может читать/менять фактор по действующим proofs и после временного отключения всех способов входа. Это не выдаёт новый login/session и не обходит suspend, auth_version, роль или сроки. Email proof не превращается в доступный метод при неготовой reauthentication capability. SMTP не нужен для password/TOTP management; операторское восстановление имеет отдельную [readiness](project-mfa-runtime.md#операторское-восстановление-проектного-mfa).

## Сборка

`projectMFA` использует общий scoped `use`: один `Registry.UsePool`, operation timeout, current catalog key до/после. Login и management создают соответствующий существующий service/repository только внутри callback; pool/service не сохраняются. На post-guard error pointer result возвращается nil, даже если SQL transaction уже завершилась; откат committed операции не обещается.

Factory переиспользует project-scoped MFA cipher/Redis limiter и immutable Config. При отсутствии active primary login coordinator она собирается из той же согласованной browser configuration без новых ресурсов. `mfapostgres.NewWithEmailProof` и `mfaservice.NewConfigured` сохраняют действующие SQL/proof/factor policies. Общий HTTP Handler используется без копирования DTO, Swagger, error mapper или crypto. Новых ENV, dependencies, schema, pools или workers нет.

## Проверки и оставшиеся границы

Добавлены prerequisites/route protection tests. Existing prepared-project password fixture расширен настоящим HTTPS MFA cycle на прежнем synthetic user: status без fresh proof, Origin/no-session отказ, enrollment/confirm, обычный MFA login через browser binding cookie, recovery step-up/rotation/deadline preservation, single-use code rejection, management после выключения primary methods, required-role disable refusal, recovery regeneration, replacement и voluntary disable. Используются прежние recovery codes в памяти и SQL-time TOTP helper без ожидания 30 секунд; фиксированный factor-attempt budget не ослабляется. Собственные SQL/policy/role/factor и точные Redis keys очищаются, parent login budgets сохраняются.

Main formatter/source review и read-only review. Luna V1 task check/API/security/affected race PASS. После ordinary MFA login fixture дополнен обязательным отдельным password reauthentication, без изменения production guards. Luna V2 targeted lint0/full Linux ARM64 TestPrepareCommandSQL PASS: project_MFA_management_HTTP и прежний project_MFA_login без skips, TLS verify-full/Redis/wrong-password denial PASS. Все 13 source hashes совпали после прогона и с main; своё окружение очищено. Snapshot/evidence — history. External-only email proof, полная two-project/cookie/roles matrix, lost-factor delivery, эксплуатация/GC/RPS и UI здесь не объявляются проверенными.
