# Закрытая подготовка проекта для владельца платформы

MP3.7a — первый этап owner-managed readiness. Luna: task check, affected race, security и actual PostgreSQL18.6 TestPrepareCommandSQL PASS, обязательные managed/legacy cases без SKIP. Полная публикация ready/HTTP/worker assembly остаётся в MP3.8/MP4.

## Граница этапа

Подготовить отдельный закрытый профиль вместо обязательного пользовательского first-admin setup. Владелец управляет проектом через platform session и последующие typed bridge APIs; проектную identity/сессию владельца не создавать. Все public methods, registration и token issuance выключены по умолчанию. SMTP и локальный администратор для такого закрытого профиля не требуются.

Переиспользовать существующий внутренний SetupProof из зашифрованных secrets, schema/binding checks и preparation markers. Proof не выдаётся человеку; pending setup row не означает обязательного создания администратора. Старый setup-only HTTP factory должен отвергать новый профиль, а старый standalone/setup сценарий остаётся прежним. Явные разные typed методы исключают неявное смешивание двух начальных policies.

CLI получает отдельный `-managed`, требующий `-password` и несовместимый с `-onboarding`. Команда только подготавливает sealed БД, не включает LOGIN и не публикует ready. Повтор не перезаписывает policy; другой начальный профиль, occupied state, orphan/tamper/binding mismatch должны отвергаться.

Для внутреннего provisioner добавить cold-open проверку закрытого managed SQL profile и отдельную физическую активацию с тем же persisted journal, свежей аутентификацией и cleanup при ошибке. Managed probe не создаёт setup HTTP admission; public runtime остаётся недоступным через catalog до отдельной корректной публикации. Простой probe не становится lifecycle transition.

## Реализованные методы

- `Target.PrepareManagedConfiguration` — общий guarded initializer с отдельной фиксированной policy: все public methods/registration/token issuance выключены. Marker, policy и private setup pin фиксируются одной транзакцией. Повтор не обновляет xmin, несовпадающая policy не перезаписывается.
- `CheckManagedRuntime` — readonly attestation текущего runtime identity/schema/grants, binding/private proof, policy version1 и выключенных функций. Pending first-admin payload/attempts отвергаются; строка setup не считается завершённой или администратором. `CheckOnboardingRuntime` сохраняет прежний password-only pending setup profile, оба профиля несовместимы.
- `PreparationRepository.ProbeManagedRuntime` — проверка текущей preparation/epoch и decrypt bound proof; не записывает `onboarding_admitted`, не меняет phase или project binding.
- `Target.ActivateManagedRuntime` — существующий opening/open/closing/closed journal, снятие старого setup admission, реальная аутентификация через новый pool, managed probe и финальная проверка catalog epoch. Ошибка закрывает LOGIN/CONNECT; повтор не переписывает journal. Метод предназначен provisioner, не HTTP API.

Параметры CLI выделены из main в `command.go`; проверки зависимостей flags выполняются до подключения. Основные lifecycle и команды подготовки используют общие существующие операции. Новых migrations/grants/schema/ENV/secrets/dependencies нет.

`project-prepare -schema -secrets -password -managed` возвращает stage `managed_configuration_prepared`; обязательные project/operation/version/generation и trusted provisioner ENV остаются прежними. CLI не запускает ActivateManagedRuntime: после команды БД по-прежнему sealed. Runtime activation — отдельная привилегированная операция, ещё без production loader/publish-ready caller.

## Проверки

Добавлены flags unit cases и actual SQL nested `managed configuration`: closed defaults без users/roles/SMTP, отсутствие proof в выводе, retry без перезаписи, отказ при смене managed/first-admin профиля в обоих направлениях. Actual TLS/SCRAM activation проверяет неверный пароль и cleanup, реальную managed attestation, запрет legacy setup admission, reject pending first-admin attempts, отсутствие ready/binding публикации и idempotent journal. Fixture восстанавливает только собственное синтетическое состояние перед старой onboarding-регрессией; реальные БД не затрагиваются.

Все исполняемые проверки — отдельный чат Luna, evidence/source и результат в [history](../planning/history.md). Подготовленный код и formatter не означают PASS. Общие TestPrepareCommandSQL нужны и для старого onboarding, поскольку initializer/activation/profile reader переиспользованы.

## Следующие условия публикации

Перед включением выбранных методов проверить их реальную сборку и проектные credentials/settings. Email OTP, подтверждение адреса, recovery/invitation и прочие включённые email-сценарии должны иметь свою готовую доставку; для проекта без email-функций SMTP не требовать. Этот этап не добавляет switches или фиктивные capabilities для ещё не собранных flow.

Финальный publish-ready требует согласованного binding/epoch, current catalog authority, crash/retry/recovery и полноценного runtime/worker lifecycle. Здесь не добавлять автоматический ready по metadata/probe, UI или SSO. Рабочие БД/env/secrets не менять, миграции и новые зависимости для этого этапа не нужны.
