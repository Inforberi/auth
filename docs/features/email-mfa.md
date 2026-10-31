# Email как дополнительный фактор

Подготовка канала A6.3m.6c.1 проверена Луной; внутреннее управление A6.3m.6c.2 проверено Луной. **Email MFA пока нельзя включить в настройках или использовать для входа.** HTTP/routes/Swagger/runtime profile/новых ENV для этого подэтапа нет. Объект EmailPreparation предоставляет request/confirm только серверному коду; его нельзя считать включённым фактором.

## Сценарии и границы

| Сценарий | Входные гарантии | Результат |
| --- | --- | --- |
| Подготовка канала — этот подэтап | Текущая browser/password session, explicit password proof моложе5m, уже подтверждённый принадлежащий пользователю email; строгий TOTP/recovery, если текущая policy/personal factor требует MFA | Почтовой possession proof и ротация существующего session token с прежними ID/сроками/primary/password/MFA proofs. Не новый вход/роль/фактор |
| Активация и выбор — внутренний .6c.2, Luna PASS | Актуальные права/политика, осознанное включение, подготовленный канал, допустимый primary/factor pair | Сохранённая привязка к контакту и отзыв credentials; публичное включение закрыто до полного enforcement |
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

## Внутреннее управление — A6.3m.6c.2

Разрешение проекта и выбор пользователя разделены. Новая колонка `auth.mfa_settings.email_factor_allowed` по умолчанию false; режим optional/administrators/required остаётся в действующей MFA policy. `settings/service.EmailMFA` читает и изменяет разрешение с тем же version, что и режим MFA: параллельное изменение любого из них требует перечитать настройки. Read/update заново проверяют `auth.settings.manage`, пользователя, session и свежие proofs. Update использует Access exclusive lock и финальный deadline, сохраняет non-secret audit. Включение требует trusted assembly readiness, передать её через запрос нельзя. Отключение запрещено, пока есть хоть одна привязка, включая приостановленную: без массового обхода пользователей, снятия защиты или автоматического fallback.

`mfa/service.EmailFactors` предоставляет внутренние Status/Enable/Disable. Enable не принимает user ID/email/method из DTO как готовую authority: Proof связывается с актуальной browser/password session, текущими credentials и version. Нужны свежий явный password proof и email possession proof той же session на verified owned contact; при действующей защите также свежий записанный TOTP/recovery. Сроки перепроверяются перед commit. Нормализация адреса уже выполнена при подготовке, повторной domain-валидации здесь нет. Mutation admission использует project-scoped MFA cipher/limiter, errors fail-closed.

`auth.mfa_email` хранит одну привязку пользователя к конкретному email ID, enabled_at и nullable suspended_at. FK проверяет принадлежность контакта, привязка не зависит от TOTP row и не исчезает при изменении общего режима. Enable/Disable атомарно меняют auth_version, отзывают все SQL/browser/native sessions, удаляют pending MFA/email OTP challenges и записывают audit. Новую session или MFA proof они не выдают; новый вход нужен даже после успешного изменения. Два конкурентных Enable с одной исходной session дают один успех. Повтор активного Enable с новым доказательством возвращает conflict; приостановленную привязку можно подготовить и включить заново.

Status различает Allowed, Configured и Usable. Последнее означает только разрешённый, неподвешенный verified канал; не готовность runtime и не выданный MFA proof. Read проверяет актуальную session/version/status пользователя, но не требует свежих proofs изменения.

Смена email, security report и protected recovery приостанавливают прежнюю привязку в существующей транзакции инвалидирования доступа и сохраняют audit. Новый verified email не наследует второй фактор. Неподтверждённый/приостановленный контакт не считается пригодным каналом, однако сам факт настроенного фактора продолжает требовать MFA: нельзя получить password-only доступ из-за потери почты или optional policy. Block/unblock сохраняет привязку и отзывает credentials; удаление аккаунта очищает её. Смена/reset пароля не удаляют независимо настроенный фактор. Recovery потерянного email-only фактора ещё не опубликован.

**Временный закрытый gate:** полноценного email login/step-up ещё нет. CheckCapability отказывает runtime с разрешённым email MFA или привязками; startup/project profiles, HTTP и новые ENV не подключены. Email-only primary не может пройти обычную выдачу сессии или попасть в first-TOTP enrollment вместо своего фактора. До .6c.3 удаление email-фактора требует действующего свежего strong proof; удаление TOTP при существующей email-привязке также закрыто, чтобы не оставить только ещё не подключённый способ. Это ограничения внутреннего этапа, не финальная политика выбора методов. Публиковать private policy с readiness=true до готовности всей цепочки нельзя.

Подготовлены unit fail-closed admission и SQL `TestEmailFactorLifecycleSchema`: shared version/permissions/readiness, one-winner активации, отзыв sessions, независимость TOTP, policy/activation race, optional email-only без обхода, block/unverify, stale/missing mail proof, audit rollback, реальная смена email и удаление. Luna: task check, affected race и пять назначенных SQL roots — PASS; manifest 25/25, cleanup подтверждён. Новых зависимостей/воркеров/публичных маршрутов нет. Исходные up/down изменены без отдельной лишней migration; реальный upgrade остаётся MP6.

## Что остаётся до публикации email MFA

1. Подэтап .6c.2 принят после Luna; runtime/profile readiness для разрешения email MFA подключать только с полным login/step-up enforcement.
2. В .6c.3 завершить выбор пригодных primary/second combinations, email-only recovery/отключение и last-factor rules; критические strong операции и требования к администраторам не понижать до email.
3. Bound login challenge, разрешённые primary/second combinations; для email-primary повторный email код запрещён. Выбор и deadline нельзя подменить клиентским assurance-флагом.
4. Атомарный consume+browser/native issuance, явный метод/assurance/JWT/introspection; слабый код не открывает strong critical operations.
5. Runtime/project/platform compatibility и readiness, параметры admission из действующей MFA configuration, защищённые HTTP методы, два проекта/конкуренция/recovery и отсутствие bypass. Только после этого публиковать флаги/маршруты, затем Telegram и UI отдельно.
