# Email как дополнительный фактор

Текущий подэтап A6.3m.6c.1 — внутреннее подтверждение канала, проверки Luna пройдены. **Email MFA пока нельзя включить в настройках или использовать для входа.** HTTP/routes/Swagger/runtime profile/новых ENV для этого подэтапа нет. Объект EmailPreparation предоставляет request/confirm только серверному коду; его нельзя считать включённым фактором.

## Сценарии и границы

| Сценарий | Входные гарантии | Результат |
| --- | --- | --- |
| Подготовка канала — этот подэтап | Текущая browser/password session, explicit password proof моложе5m, уже подтверждённый принадлежащий пользователю email; строгий TOTP/recovery, если текущая policy/personal factor требует MFA | Почтовой possession proof и ротация существующего session token с прежними ID/сроками/primary/password/MFA proofs. Не новый вход/роль/фактор |
| Активация и выбор — следующий подэтап | Актуальные права/политика, осознанное включение, подготовленный канал, допустимый primary/factor pair | Активный factor binding/preference, отзыв затронутых credentials; до готовности enforcement не публиковать |
| Завершение email MFA login — следующий подэтап | Подтверждённый primary, bound challenge, разрешённый активный фактор/канал, одноразовый код | Consume+session/native issuance в одной transaction с явным слабым методом; не TOTP/strict authority |

Первый компонент принимает только password primary. Email OTP и OIDC не допускаются: дополнительный код после email primary нельзя назвать независимой MFA; для внешнего provider нужна отдельно согласованная policy независимости канала. API/native session не принимается. Подтверждённый контакт сам по себе не означает согласие включить MFA.

## Подготовка канала

`service.NewEmailPreparation(repo,cipher,limits,tokens,cfg)` получает project-scoped email-login cipher/Redis limiter, не чужой default secret. Config задаёт TTL1..5m, resend interval1s..<TTL и положительные project request/confirm budgets. Сборка в startup/project profiles пока закрыта до следующих подэтапов: этот компонент не создаёт новый публичный способ входа.

`Request(ctx,proof,email,ip)` берёт proof из доверенного текущего session context, не из произвольного JSON. Domain один раз нормализует email. SQL под Access snapshot/user/session/password locks проверяет пользователя/version/status, browser/password primary, explicit password freshness, текущую строгую MFA при необходимости, отсутствие temporary/pending provisioning и принадлежность verified email. Чужой/неподтверждённый адрес не создаёт outbox. Фиксируются email ID, auth_version и исходный session hash. Deadline ограничен TTL, session/password/MFA freshness и перепроверяется перед commit.

Код — восемь случайных цифр, binding —256bit; наружу коду не возвращается plaintext OTP. Verifier/digest имеют отдельный prefix `mfa-email-prepare:`, challenge purpose=`mfa_email_prepare`; encrypted payload использует существующий email-login cipher и JSON to/subject/body. Challenge/outbox/audit создаются атомарно. Resend заменяет только это назначение и не продлевает account-wide guessing budgets.

`Confirm(ctx,EmailPreparationConfirmation)` повторно проверяет текущую session/права канала/version/freshness и точное назначение. Пять неверных попыток коммитятся и удаляют отработавший outbox, не откатываются с публичной ошибкой. Успех потребляет code один раз, ротирует только исходный session token и записывает email_reauthenticated_id/at. Возвращается новый token текущей session, а не новый login; MFA method/time, password proof, роли/auth_version и сроки не повышаются. Другой session того же пользователя не может подтвердить intent. Audit/SQL failure откатывает rotation/consume вместе; повтор со старой cookie/перенесённый код не даёт authority.

Этот email possession proof — предпосылка будущей активации, не её выполнение. TOTP/recovery и RequireStrongMFA для критических операций сохраняются. Если текущая MFA policy не требует фактора и его нет, свежий парольный пользователь может подготовить канал, но это не включает MFA незаметно.

## Переиспользование и нагрузка

Расширены существующие email_login_challenges/outbox/audit, отдельного worker/очереди/таблицы фактора нет. UNIQUE(user_id,purpose) ограничивает pending intents тремя назначениями; native/browser primary login по-прежнему заменяют одно общее login intent. Legacy request удаляет только свой purpose. Security revocation/reset/retention по-прежнему могут удалить все intents пользователя. Target tuple immutable, ownership FK и expiry/lease indexes сохранены.

Delivery проверяет актуальность канала/source session/password/строгой MFA на своей ветке и использует прежний sender, lease/retry/expiry cleanup. Нет keyspace scans, горячих full-table проходов или синхронной SMTP в request. Redis budgets purpose/user/IP/project; ошибки admission fail-closed. Перед HTTP подключением понадобятся profile readiness/route/CSRF/source-cookie и реальные scoped Redis приёмки — этот срез их не объявляет проверенными.

Schema меняется в исходной prerelease migration; реальные DB/ENV не менялись, upgrade существующей БД отдельно MP6. Подготовлены unit crypto/admission и TestEmailFactorPreparationSchema: purpose coexistence, owned channel, no authority/lifetime increase, one-winner/replay/attempts, stale/revoked/unverified/primary/native guards и audit rollback. Luna: task check, emailotp race, TestEmailFactorPreparationSchema, TestPostgresSchema и TestTwoProjectEmailOTPHTTPIsolationSQL — PASS; manifest 24/24, тестовый стенд очищен.

## Что остаётся до публикации email MFA

1. Сохраняемая project policy разрешённых методов и личный выбор/активация с версией, аудитом, повторной проверкой и отсутствием auto-downgrade.
2. Явный email-factor binding к verified contact, правила смены/удаления адреса, last-factor/recovery; не привязывать email-factor lifetime к TOTP только ради упрощения кода.
3. Bound login challenge, разрешённые primary/second combinations; для email-primary повторный email код запрещён. Выбор и deadline нельзя подменить клиентским assurance-флагом.
4. Атомарный consume+browser/native issuance, явный метод/assurance/JWT/introspection; слабый код не открывает strong critical operations.
5. Runtime/project/platform compatibility и readiness, защищённые HTTP методы, два проекта/конкуренция/recovery и отсутствие bypass. Только после этого публиковать флаги/маршруты, затем Telegram и UI отдельно.
