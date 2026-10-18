# Изоляция Redis и шифрования — MP2.3-realm-scope

18 октября 2026. Реализован внутренний scope-контракт перед подключением операторского Auth. **Второй realm и новые HTTP endpoints не опубликованы.** Текущий runtime использует явный legacy scope; рабочие данные/ENV/ключи не мигрировались. [План](../planning/multi-project.md), [ADR005](../adr/005-independent-projects.md).

## Идентификатор области

`internal/infra/realmscope` создаёт неизменяемый scope только из `platform` или `project` и canonical lowercase nonzero UUID. Эти значения передаёт доверенная сборка, не запрос пользователя, slug, email или claims JWT. Пустое значение не означает legacy: assembly и scoped constructors его отвергают.

`Legacy()` предназначен только для прежней single-project установки. Он сохраняет точные Redis prefixes, cipher purposes и HMAC namespaces. Это явный профиль совместимости, не fallback после ошибки расшифровки. Новую platform/project область нельзя собирать в legacy режиме.

## Redis

Согласовано: текущий выпуск сохраняет PostgreSQL + обязательный Redis. SQL-only backend и автоматический fallback при отказе Redis сейчас не реализуем. Общий Redis допустим с realm namespaces; отдельные инстансы дают изоляцию ресурсов/отказов, но не требуются автоматически для каждого проекта.

Scoped prefix имеет вид `auth:{realm:<kind>:<uuid>:<purpose>}:`. Realm и назначение входят внутрь hash tag: ключи одного Lua budget script имеют общий tag, но не общий tag всех проектов. Это не объявление Redis Cluster support: текущий клиент остаётся standalone `*redis.Client`, cluster/fleet не проверялись.

Подключены все активные Redis adapters текущей assembly:

| Сценарий | Назначение scope |
| --- | --- |
| Account verification/setup/binding | `email-verification-limit` |
| Password/login/recovery/temporary, email OTP | `password-limit` |
| MFA/recovery/admission | `mfa-limit` |
| SMTP test | `smtp-test-limit` |
| JWT exchange/native issuance | `jwt-issuance` |
| Native credential lookup | `jwt-refresh-lookup` |
| Introspection | `jwt-introspection` |
| OIDC state/binding/limits | `oidc-google`, `oidc-telegram` |

Разделены не только digested actor/IP keys, но и literal global/project budgets. Prefix вычисляется при сборке, дополнительных Redis round trips нет. Lua algorithms, TTL и policy limits сохранены. Старый session Redis adapter **не подключён** и остаётся legacy-only; сессии обслуживает SQL authority, не новый кеш.

При ошибке Redis простые account/password/MFA/SMTP лимитеры теперь возвращают `allowed=false` вместе с ошибкой. Ранее значение могло быть true из-за zero result, хотя сервисы проверяли error первым. Это уточнение fail-closed контракта, не утверждение ранее доказанного обхода ограничения.

## Шифрование и HMAC

`app/auth/realm_security.go` создаёт прежний `secretbox.Cipher` с purpose `realm:<kind>:<uuid>:<feature-purpose>`. Realm входит в AEAD additional authenticated data и HMAC namespace. Даже при одинаковом root key ciphertext одного realm не открывается в другом, digest одинакового значения различается. Legacy purpose/digest остаются прежними, включая особый namespace email verification.

Область передаётся в verification/outbox, binding, initial setup, password reset/temporary/login limits, TOTP/recovery, email OTP, SMTP/provider settings, OIDC flow и JWT limiter digest. Password assembly сгруппирована в `app/auth/password.go`, чтобы связанные сервисы/лимиты/cipher не смешивались с остальной assembly.

Namespace **не заменяет независимые deployment keys**, issuer/signing keys, SQL storage marker, runtime grants или exact origin/cookie/CSRF guards. Provisioning/key ownership и host routing ещё впереди. Existing operational recovery tools пока legacy-only; для нового operator profile нужен явный scoped recovery и drill. Автоматический re-encryption, legacy decrypt fallback и смена настоящих ключей не добавлены.

## Проверки

- Unit: некорректный/zero scope; realm-kind/UUID/purpose и hash tags; compatibility legacy purposes/prefixes; все scoped adapters отвергают zero scope. Crypto проверена для одиннадцати назначений между legacy/platform/project с одинаковым UUID и другим project UUID, намеренно одинаковым root key; cross-decrypt запрещён, legacy decrypt/digest сохранены.
- Реальный Redis8.2.6/Linux arm64: `TestRealmRedisIsolation` PASS0.01s в явной пустой DB15 существующего sandbox. Account/password/MFA/SMTP budgets/TTL, parallel MFA admission, JWT issuance/native/lookup/introspection global budgets, OIDC provider/realm/binding/TTL/encrypted payload/single consumption, legacy old/scoped constructors и cancellation. Для JWT/OIDC намеренно использован одинаковый digester/cipher между realm, чтобы проверить именно prefixes, независимо от crypto separation.
- Финальные `task check` PASS/lint0 и targeted race PASS. Race выполнялся для unit tests, opt-in Redis под race не запускался; standalone Redis acceptance — отдельный Linux binary без race.
- Cleanup удаляет только заранее зарегистрированные fixture keys, без SCAN/FLUSHDB/FLUSHALL. DB15 вернулась к0, DB0 count0 остался0. Scratch binary/пустой каталог удалены, остановленный до проверки Redis возвращён в stopped. PostgreSQL/API/прочие контейнеры не запускались.

NOT RUN: два полноценных Auth runtime/HTTPS/cookies/ingress/SQL/grants, independent key provisioning/rotation/recovery/cutover, Redis Cluster/fleet/outage/load/GC/capacity. Scoped codecs/adapters не закрывают эти gates и не разрешают публикацию management bridge.
