# JWT независимого проекта

MP4.1k, 25 октября 2026. Реализация и локальные проверки Luna V1–V3 завершены успешно.

- Переиспользовать существующие token exchange/native/refresh/logout, SQL ledger и signer. Signer получает ранее подготовленный project signing key через отдельный узкий read-only loader; без ENV/file fallback, новых ключей, schema или зависимостей.
- Issuer/resources/TTL — trusted project assembly config, текущая SQL policy управляет допустимостью выдачи. Issuer должен быть уникальным для проекта; полноценная привязка host/issuer/cookie и публичные routes/readiness остаются MP5, здесь не публикуются.
- Resident component хранит signer, копию config и ограничение одновременных операций. Request-local service/repo используют только один UsePool с current key до/после; не сбрасывать admission при каждой сборке сервиса. SQL signing/commit/revoke/auth_version/role/MFA/refresh-reuse guards сохраняются.
- Один shared no-retry Redis owner для JWT на процесс, bounded pool; проектные HMAC/scopes и budgets отдельно. Primary/MFA используют существующий shared Redis/hasher. Нет нового JWT Redis pool на каждый проект.
- Native password/email OTP используют существующие primary и MFA coordinator, audience/scope-bound challenge и общую SQL issuance transaction. Browser session/challenge не подставляется в native flow. Loss-all-factors recovery закрыт.
- JWKS возвращает только project public key через актуальный runtime. Key rotation следует замене доверенного runtime snapshot, не произвольному выбору kid/issuer из входного токена. Overlap/emergency/fleet policy и consumer HTTP readiness — отдельные gates.
- Main formatter/diff; Luna task check, affected race, actual SQL/Redis exchange/native/refresh/replay/revoke/crypto isolation на disposable fixtures. Не заявлять offline JWT немедленно отозванным SQL block: strict online и local expiry имеют существующие разные гарантии.

## Сборка и владение

`NewProjectTokens` создаётся один раз на доверенный runtime key как ограниченный resident component, не заново на каждый запрос. Он получает `ProjectTokenConfig` и общие registry/private reader/Redis/hasher. Credentials codec возвращает отдельный redacted `SigningKey`; его `Use` очищает переданный PEM-буфер при любом исходе. Existing codec по-прежнему проверяет весь зашифрованный bundle: отсутствие временных копий Go-строк/EC scalar в heap не обещается. Ни database password, ни setup secret не попадают в signing view или JSON.

`signing.FromPrepared` строит только публичные метаданные из подготовленного P-256 ключа и применяет прежний строгий signer. Генерации новых ключей, записи файлов и fallback нет. `Service.Factory` хранит immutable resources/native policy и admission8; `Bind` создаёт короткоживущую привязку к SQL repository без сохранения pool в factory. Admission общий для всех привязок компонента. Signer также сохраняет свой прежний crypto admission.

`NewProjectTokenRedis` создаёт один process-owned no-retry client с pool/active/idle ceiling8, MinIdle0 и ожиданиями/таймаутами1s. Он заимствуется проектами и закрывается владельцем после drain. Конструктор проекта отвергает client с retries, неограниченными connections или неподходящими timeout. В go-redis v9.19.0 input MaxRetries=-1 после инициализации виден как Options().MaxRetries=0; проверено в установленном source и Context7. Обычный primary/MFA Redis client не перенастраивается.

## Внутренние методы

| Метод | Поведение |
| --- | --- |
| `Exchange` | Проверяет project principal/session/grants и выдаёт короткий JWT после SQL commit. |
| `PublicJWKS` | Возвращает копию публичного ключа только актуального runtime. |
| `LoginPassword` | Применяет существующий bounded hash/login admission, затем native issuance либо ограниченный MFA challenge. |
| `RequestEmail`, `ConfirmEmail` | Сохраняют native audience/scope-bound одноразовый код и выдают API session/refresh либо native MFA challenge. Browser code не используется вместо native. |
| `CompleteNativeMFA` | В одной прежней SQL transaction потребляет фактор/challenge и создаёт API session/family/tokens. |
| `StartNativeEnrollment`, `ConfirmNativeEnrollment` | Выполняют прежнюю обязательную установку фактора; сами не выдают обычную сессию. |
| `Refresh` | Ротирует refresh verifier; повтор использованного секрета отзывает family по существующим правилам. |
| `Logout` | Отзывает family и связанную authority по существующему SQL-контракту. |

Native profile опционален через `Tokens.Native`; password/email flags выбираются независимо. MFA.Enabled в конфигурации native означает доступность coordinator, а не обязательный фактор для каждого пользователя: необходимость фактора определяют текущие user/role SQL правила. Refresh-only component может не включать новые primary flows. Native email требует сохранённый SMTP и доверенную allowlist; outbox обслуживает существующий project delivery runner.

Текущие `token_session_exchange_enabled`/`token_native_enabled` и public method policy проверяются в SQL. Caller не задаёт `CheckPolicy`. Config/resources/native policy копируются при сборке. Project epoch/current guards действуют до/после операции; недоступная SQL/Redis не разрешает выдачу. Уже committed действие не обещает rollback при потере ответа или последующем final guard.

## Проверки и оставшиеся gates

Добавлены unit key redaction/binding/buffer consumption, signer issuer/foreign-key (в том числе одинаковый kid), shared Factory admission без сохранения repo, disabled/native и no-retry Redis validation. Actual command fixture проверяет project exchange/signature/issuer rejection, native password/API profile, refresh rotation/reuse, native email/logout, native MFA/browser challenge separation/replay и block denial; exact owned Redis/SQL cleanup.

Main formatter/diff review; Luna: task check/lint0 и affected race PASS; security V2 PASS (нет вызываемых кодом уязвимостей, одна в dependency не вызывается по scanner); token/native TestPostgresSchema PASS; полный TestPrepareCommandSQL на Linux ARM64/PG18.6 TLS/SCRAM/Redis8.2DB15 PASS exit0 после исправления профиля тестового стенда. Manifest20 совпал до/после и с main. Собственные containers/network/certificates/binary удалены. Проектная introspection реализована [отдельным блоком](project-introspection-runtime.md). HTTP/JWKS endpoints, управляемый источник consumer credentials, маршрутизация/уникальность issuer в каталоге, overlap/emergency project key rotation, eviction/fleet budgets/GC/RPS и MP5/MP7 приёмка остаются открытыми. Подготовленный проект сейчас имеет один signing key; этот блок не создаёт API ротации. Crypto-only проверка JWT не проверяет текущие SQL block/revoke; прежний strict online contract обязателен для немедленной authority, local сохраняет оговорённое окно до expiry. UI не начинать.
