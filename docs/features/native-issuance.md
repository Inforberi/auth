# Первая API issuance — J4b.2a-local

17 октября 2026: реализована атомарная выдача API session + access JWT + первой refresh family от проверенного пароля. **Это внутренний use case, не опубликованный native login API.** App не передаёт NativePolicy, native HTTP/ENV нет. `JWT_ENABLED` по-прежнему включает только cookie exchange/JWKS. Native MFA/email OTP binding и transport — следующий блок.

## Границы кода

| Код | Ответственность |
| --- | --- |
| `password/service/authenticate.go` | Общий password parse/admission/policy/hash/rehash pipeline, возвращает server-only PrimaryProof без создания session |
| `password/service/login.go` | Существующий browser/private-admin login использует тот же pipeline и прежний session/MFA coordinator |
| `mfa/service.ValidPrimary`, `mfa/repository/postgres.RequireLoginPrimary` | Общие форма и SQL-актуальность primary proof, без копирования guards в token |
| `token/service/native.go`, `native_policy.go` | Валидация server input/policy, ресурсы, admission/budgets, независимые credentials и результат после commit |
| `token/repository/postgres/native.go` | Final user/primary/MFA guards, API ledger/family/sign/audit/commit в одной transaction |
| `token/repository/postgres/issuance_audit.go` | Общий metadata audit/final SQL expiry guard для exchange, refresh и первой issuance |

`PasswordService.Authenticate` не выполняет полный вход. Proof содержит user/version, проверенный credential reference и время; это не bearer credential, не JSON DTO и не доверенное тело HTTP. Его нельзя отдавать клиенту, логировать или принимать обратно. MFA не считается пройденным после password proof.

## Последовательность

1. Пароль проверяется существующим bounded hasher, login limits/early policy и rehash. Ни browser session, ни MFA approval при Authenticate не создаются. Нынешние browser/private-admin сценарии продолжают пользоваться прежними ответами и coordinator.
2. `IssueNative` принимает только server-owned password proof и audience/scope/agent/trusted IP. Administrative intent, OIDC и email OTP пока отклоняются: native-purpose binding для них не готов. Неверные audience/duplicate/unknown scopes отклоняются общей с exchange проверкой; requested scope копируется и сортируется.
3. Общий instance admission8/deadline3s и атомарный Redis actor/IP/project budget применяются до issuance SQL. Counters общие с exchange, existing config/pool/no-retry semantics сохранены. **Family ещё нет:** пустой session ID не превращается в общий лимит10 для всех native logins и не создаёт empty-session key. Password hashing имеет собственные прежние admission/budgets; deadline3s относится к последующей issuance.
4. Генерируются два независимых canonical256-bit секрета. Ledger secret нужен только для SQL verifier и не возвращается клиенту. Refresh verifier не совпадает с ledger verifier; наружу после commit выходит только refresh secret и signed access result.
5. Read Committed transaction: Access shared snapshot → active user SHARE с проверкой версии и свежести proof → текущий primary reference/public policy → MFA/factor requirement. Возраст password proof <1min, допускается backend/DB skew до5s; future timestamp при записи clamp к SQL time. Password replace/reset/block/policy/grant races не дают использовать старое состояние. Redis/сеть/hasher не выполняются под этими locks.
6. Если factor уже enrolled или роль требует MFA, возвращается ErrMFARequired **без session/family/tokens**. Пока это отказ, а не native restricted challenge; публиковать такой незавершённый login как готовую MFA поддержку нельзя.
7. Создаётся сразу API-profile session, не browser session с последующим exchange. Current role-bound session/grants/provisioning guards общие с exchange. Public policy уже проверена и удерживается RequireLoginPrimary — повторный SQL policy lookup не нужен. Создаются family/первый verifier, выполняется общий local signing и metadata audit/final expiry guard, затем commit. При ошибке result=nil; подтверждённый SQL/sign/audit/commit abort откатывает все новые rows.

Потерянный ответ commit может оставить неизвестный клиенту **committed** результат: rollback нельзя обещать при любой сетевой ошибке. Raw credentials всё равно не возвращаются без подтверждённого commit, автоматического повтора нет. Требуется новый вход; недоступная клиенту session может остаться до expiry/retention или отзыва owner. Deferred SQL commit failure проверен, реальный lost-commit-reply/fleet drill остаётся внешним gate.

Primary method — password; auth_time берётся из проверенного proof с SQL clamp. MFATime и password_verified_at отсутствуют: обычный primary login не становится MFA или fresh private-admin step-up. Initial access scope должен целиком входить в текущие grants и resource allowlist; family фиксирует этот максимум. Дальнейший [refresh](refresh-storage.md) пересекает максимум с актуальными grants и не расширяет его из-за новой роли.

## Сроки и конфигурация

NativePolicy — optional server-only constructor config, не ENV/UI/API. Без неё core возвращает ErrNativeDisabled; нынешний App её не задаёт. Policy копируется при construction, а не хранит изменяемый caller pointer.

- Idle TTL ≥1min и ≤ существующего SessionTTL; absolute ≥idle и ≤ AbsoluteSessionTTL; целые секунды.
- Административные idle/absolute/activity bounds берутся из существующей session policy. Для API creation они дополнительно ограничены native idle/absolute; activity interval не превышает1/10 effective idle. SQL session trigger по текущим permissions выбирает строгий admin profile.
- Expiry access ≤ current idle/absolute. Refresh family фиксирует session absolute deadline; refresh не повышает primary/MFA assurance и не является admin activity.
- Корневые ключи, issuer, ресурсы и общий service ownership не менялись. Новых pools/workers/dependencies/schema/migrations нет; source000001 upgrade requirements J4a остаются прежними.

## Что осталось до native API

Нужны native purpose/transport/audience/scope-bound primary и MFA/enrollment challenges, одноразовая completion в той же issuance transaction, email OTP request/consume binding, first session output после MFA и HTTP contracts. Browser challenge нельзя просто передать в native completion или наоборот. Direct provider handoff — отдельный J4c.

Затем refresh/logout HTTP: bounded JSON, cookie/Authorization conflict rejection, safe mapper/Retry-After/no-store/без Set-Cookie, management profile label и negative/concurrency API tests. Перед публикацией — deployment config/ceilings, retention candidate-scan/held-ledger backlog/drain/storage, strict consumer J5 и внешние security/load/restore gates. Внутренние SQL/unit tests не доказывают готовность native клиента, capacity или отсутствие GC/memory проблем.
