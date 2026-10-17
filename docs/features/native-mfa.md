# Native MFA — J4b.2b.1-local

17 октября 2026: реализовано внутреннее завершение password + TOTP/recovery-code входа в API-профиль и обязательная настройка TOTP. J4b.2b.2 подключает [email OTP primary](native-email-otp.md) к тому же workflow. **App/HTTP/ENV не подключены.** Direct native Google/Telegram — J4c. `JWT_ENABLED` пока публикует только существующий cookie exchange/JWKS.

## Операции и владельцы

| Внутренний метод | Назначение |
| --- | --- |
| `token/service.NativeLogin.Begin` | Server-owned password/email OTP proof → готовые API credentials либо только restricted challenge |
| `token/service.NativeLogin.Complete` | Native token/binding + TOTP либо recovery code → credentials после commit |
| `mfa/service.Login.StartNativeRequiredEnrollment` | Native enrollment-required challenge → TOTP enrollment candidate |
| `mfa/service.Login.ConfirmNativeRequiredEnrollment` | Подтверждение candidate → recovery codes, version bump/revoke и новый primary login |
| `mfa/repository/postgres.CompleteNativeFactor` | Locked challenge/user/primary recheck и существующий factor consume в transaction внешнего repository owner |
| `token/repository/postgres.CompleteNativeMFA` | Factor outcome → current resource/session/grants/family/sign/audit/challenge delete/commit |

HTTP-ручек для этих методов ещё нет. Входной PrimaryProof и NativeAttempt — server-only материал, не клиентский JSON и не доказательство уже пройденного MFA. NativeAttempt содержит только найденного owner для admission, digest/binding и локальную функцию проверки; owner и challenge повторно проверяются под SQL locks.

## Привязка challenge

В существующей `auth.mfa_login_challenges` добавлены credential_profile (`browser` default / `api`), native_audience и native_scope. Для browser native-поля NULL; API challenge допускает только non-administrative password/email OTP proof, bounded audience и максимум64 scope keys/2048 bytes. У одного digest profile/target/binding неизменяемы через SQL trigger. Переход к другому target требует нового challenge.

Native использует HMAC namespaces `native-login:` и `native-binding:`, browser — прежние `login:` и `browser:`. Даже если внутренний caller перепутает digest namespace, SQL profile filters запрещают cross-redemption. Browser completion/enrollment/recovery и operator recovery approval исключают API challenge. Native completion/enrollment не принимает browser challenge. Native target сортируется/копируется перед хранением, не удерживает mutable caller slice.

**Один активный MFA login challenge на пользователя**, как в исходном browser workflow: новый native или browser primary заменяет предыдущий challenge, независимо от устройства. Старые token/binding перестают работать; это может потребовать повторить вход в другой вкладке/на другом устройстве. Уже созданные sessions не объединяются и сохраняют свой ledger. User guessing budgets общие между профилями, новая primary challenge не сбрасывает factor-user counter.

## Завершение MFA

1. Begin использует существующую первую primary issuance. Если MFA не нужен — возвращает credentials. Если SQL требует MFA — новый transaction snapshot повторно проверяет primary/current policy/version и сохраняет только native-bound challenge. Это два bounded SQL workflows при MFA requirement, не второй password Compare/rehash или email consume. Готовая browser session не создаётся и не перепаковывается в JWT.
2. Complete ограничен общим с exchange/issuance instance admission8 и deadline3s. До MFA subject keys и SQL lookup выполняется общий с refresh атомарный credential IP/project budget: случайный challenge не обходит resource admission и не создаёт безлимитный поток subject keys. Затем shape/существующие MFA subject/IP/project/user/factor-user budgets и token actor/IP/project budget — до final SQL transaction. Общий port называется AllowCredentialLookup, исторический Redis key tag `auth:{jwt-refresh-lookup}` сохранён для совместимости counters; Lua/TTL/no-allocation-on-denial не менялись. Redis/сеть/hasher не выполняются под SQL locks. MFA standalone start/prepare/enrollment имеют bounded5s context, clipped к внешнему deadline.
3. Repository owner берёт Access shared snapshot → user UPDATE → challenge UPDATE → factor locks. Проверяет active user/current version, profile/digest/binding/TTL/attempts, administrative/enrollment intent, первичный method/reference и актуальную public policy. Audience/scope берутся из locked SQL target, не из completion input.
4. Используются те же TOTP anti-replay step и recovery-code deletion/audit, что для browser MFA. Неверный factor увеличивает attempts и возвращает Rejected outcome: owner **коммитит попытку до отказа**. Wrong binding/profile не расходует чужие SQL attempts. После5 попыток challenge закрыт. Dependency failure не выдаётся за неверный код и не расходует factor.
5. Для успешного factor текущий deployment resource allowlist проверяется заново; общая issuance проверяет grants/role bindings/provisioning, создаёт сразу API ledger/family, подписывает access локально и записывает audit. Перед commit удаляется только ещё живой native challenge и пишется MFA completion audit. Factor, challenge, API rows и audits участвуют в одной transaction. SQL/sign/audit/подтверждённый commit abort возвращает nil и восстанавливает расход фактора/challenge; повтор после успешного commit не создаёт вторую session.

MFATime берётся из SQL-времени реального consume. Primary auth_time сохранён, password_verified_at остаётся NULL: native MFA не становится private-admin password reauthentication и не открывает cookie admin handlers. Claims содержат `pwd` либо `emailotp` + `mfa`; ledger не выдумывает детализацию TOTP/recovery, которой не хранит. Refresh использует общую authority и не повышает assurance или admin activity.

При потере ответа commit результат может быть неопределённым. Raw credentials не возвращаются без подтверждённого commit, автоматического retry/grace нет; нужен новый вход. Нельзя обещать rollback уже committed операции. Этот сетевой fault/fleet drill остаётся внешним gate.

## Обязательная настройка и ограничения

Role-required enrollment возвращает только challenge с EnrollmentRequired. Native enrollment использует существующие secret encryption, TOTP check, recovery generation и invalidateFactors. Успешная настройка повышает auth_version, отзывает прежние sessions и удаляет старые challenges. Она не выдаёт access/refresh: нужен новый primary login, новый native challenge и проверка фактора. Browser enrollment/confirmation не могут завершить native candidate и наоборот.

Recovery code поддержан как MFA factor. Восстановление при потере **всех** факторов остаётся существующим browser/operator workflow, не native redemption. OIDC primary в native MFA пока запрещён, а новые factor types/пустые adapters не добавлены.

Изменена только source000001 up/down; отдельной миграции нет. Новый binary ожидает challenge profile/target columns и trigger **даже при выключенном native профиле**, поскольку browser SQL также использует profile filters. Перед deployment нужен controlled schema/grants upgrade; рабочая БД не менялась и не сбрасывалась. Existing retention очищает native challenge/enrollment по тем же indexed expiry batches; новых tables/workers/pools/dependencies нет.

Далее: App/native configuration и HTTP login/MFA/enrollment/refresh/logout, explicit cookie/Authorization conflict rejection/no-store/safe errors, management profile label и API negative tests. J4b.2c.1 добавляет общий [atomic MFA admission](mfa.md#атомарный-admission--j4b2c1-local), работающий и при JWT disabled: budget denial не выделяет random subject/IP keys и не расходует batch частично. Native token prelookup дополнительно сохранён; стадийный accounting описан явно. До публикации остаются strict consumer J5, retention/drain/storage/deployment, HTTPS/browser/provider/SMTP/fleet/restore/load/GC gates. SQL/unit/race PASS не означает измеренную capacity или production sign-off.
