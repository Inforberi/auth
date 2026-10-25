# Настройки авторизации проекта из платформы

MP2.7: реализация и локальные проверки Luna завершены (V1–V5). Scope — основная несекретная Auth policy, её чтение и полная замена, включая методы входа, регистрацию, email verification и issuance switches. SMTP/provider secrets и их probes остаются отдельными сценариями. UI не добавляется.

## Принятые границы

- Current `platform.project_settings.manage` и fresh password/MFA, exact ready/enabled project binding, browser/session/capacity guards. Operator не копируется в project users.
- Изменение использует durable intent и committed admission до 3 секунд, затем bounded project transaction. Отзыв запрещает новые admissions, уже допущенная команда может завершиться в коротком окне.
- Отдельные append-only catalog intents/admissions и project receipt/audit; общего RPC/skipAuth нет. Completion читается из project receipt по своей операции при current authority: проект должен быть доступен. Offline catalog completion cache не добавляется.
- Expected project version/generation и policy version, immutable request/op UUID, повтор без повторной записи, no-op без UPDATE settings, audit/receipt атомарны с policy. Unknown commit не считается rollback; тот же запрос или GET операции восстанавливает результат.
- Domain-валидация и SQL persistence переиспользуются с локальным settings API. Его current local actor/fresh-auth/last-admin/audit сохраняются. Platform mutation не требует локального администратора: независимый владелец остаётся в platform authority; публичная Policy не отключает административные password/MFA endpoints.
- Readiness — факты trusted assembly, не поля запроса. Полный project Auth ещё не собран, поэтому production bridge сообщает закрытые capabilities и отвергает включение неподготовленных функций. Хранение Client ID/secret само по себе не доказывает работоспособность провайдера или доставки.
- Policy changes сохраняют прежнюю семантику: не отзывают уже выданные project sessions/JWT автоматически; текущие login/issuance guards применяются к новым операциям. Массовых UPDATE users/sessions не добавлять.

Новые таблицы в initial schema, точные grants/runtime guards/checksum и live SQL regression входят в блок. Рабочие БД/ENV не меняются; новые upgrade migrations/dependencies не добавляются. Старым БД нужен controlled upgrade.

## API

Только operator profile с opt-in project runtime; session cookie, exact Origin и существующий project capacity admission. Все ответы `Cache-Control: no-store`, сессия не продлевается. Требуются `platform.project_settings.manage` и свежие password/MFA.

| Метод | Путь после `/api/v1/platform/projects/{id}` | Назначение |
| --- | --- | --- |
| GET | `/auth/settings?expectedVersion=…&expectedGeneration=…` | Текущая policy, её версия и доступность методов без секретов |
| POST | `/auth/settings` | Полная замена policy; поля ниже обязательны |
| GET | `/auth/settings/operations/{operationId}` | Результат только собственной операции для этого проекта |

POST принимает `operationId`, `expectedVersion`, `expectedGeneration`, `expectedPolicyVersion`, `reason`, `policy`. Структура policy совпадает с [локальным settings API](auth-settings.md): `methods.password/emailOtp/google/telegram`, `registration.enabled/google/telegram`, `passwordEmailVerification`, `tokenIssuance.sessionExchange/native`. Все boolean передаются явно, включая false. Неизвестные поля, query, неполная policy и тело больше 8 KiB отклоняются. SMTP/provider secrets и deployment в этом запросе не принимаются.

Ответ POST: `operationId`, `status`, `settings`, `changed`, `replayed`. При известном commit — 200; при потерянном подтверждении commit — 202, `status=unknown`, без settings/changed. `Location` ведёт к GET операции. Повторять тот же operation UUID и неизменный payload: новая операция не является безопасной заменой повтора. Конфликт project/policy versions — 409; неподготовленная функция — 409 `auth_method_not_ready`; неинициализированная policy — 409 `auth_settings_not_initialized`; отсутствующие права — 403; нужна свежая аутентификация — 428; перегрузка — 429; недоступность SQL/runtime — 503. Ошибки драйвера наружу не передаются.

GET операции не создаёт admission и не повторяет mutation. Возвращаемая settings — исторический снимок commit, не обещание текущего состояния. Нужны текущие права и доступный ready/enabled проект с первоначальными binding/version/generation. После suspend/rebinding или при offline SQL чтение отклоняется; offline outcome cache здесь намеренно отсутствует. UUID другой операции/проекта/оператора не раскрывает результат.

## Готовность и текущее ограничение

До MP5.1e production assembler передавал пустые capabilities: `availableMethods` — false, token deployment выключен. Можно сохранять закрытую policy и dormant настройки регистрации/verification, но включение входа или issuance отклонялось до сборки Auth. Это административный API, не публикация normal Auth traffic.

В проектном пути нет ENV fallback для Google/Telegram: дополнительно требуются сохранённые provider settings. Email OTP и password verification optional/required требуют trusted delivery readiness и сохранённый SMTP. Для password без verification, Google/Telegram-only либо dormant verification SMTP не становится общим искусственным условием. Recovery/уведомления проверяются своими сценариями; эта policy не объявляет их readiness. SMTP row и secret_set сами по себе не подтверждают сетевой probe.

Тесты с synthetic trusted adapters проверяют SQL rules/atomicity и не доказывают готовность production assembler. Инициализация policy остаётся отдельной подготовкой: GET ничего не создаёт.

## Хранение и нагрузка

Каталог: append-only `platform.project_auth_policy_intents` и `platform.project_auth_policy_admissions`. Проект: append-only `auth.platform_auth_policy_updates`, одновременно receipt и аудит (platform realm/actor/admission, exact binding/request, before/after и changed). Нет FK platform actor → project user, копий identity и массовых обновлений сессий. Settings update и receipt входят в одну проектную транзакцию под существующим Access lock. PK operation UUID обеспечивает точечный replay; no-op не переписывает policy. Общие с role bridge короткая транзакция, target guard и intent SQL helper не принимают SQL/имя таблицы от клиента.

Runtime получает только необходимые INSERT-колонки receipt, SELECT, без изменения/удаления receipt и подмены времени; catalog intent/admission также append-only. Обновлены initial SQL, grants и profile/checksum guards. Рабочие БД не обновляются автоматически; controlled upgrade существующих БД — отдельная операция. Retention этих административных receipts не добавлена: удаление потребует отдельного согласованного срока и сохранения гарантий идемпотентности.

## Проверки

Добавлены HTTP shape/error/unknown-result tests, router Origin/session/capacity/opt-in и Swagger contract, live SQL policy/update/replay/no-op/atomic rollback/provider/delivery/current authority/concurrency/lost commit сценарии внутри `TestPrepareCommandSQL`, а также negative ACL cases для receipt. Luna: task check, affected race, API reproducibility, security scan, operator SQL/HTTPS, runtime assembly и local Auth settings/provider/token/public-policy SQL PASS. Финальный V5 full TestPrepareCommandSQL PASS без SKIP, включая policy unknown commit/concurrency и subsequent onboarding/managed cases; targeted lint PASS (0 issues). Manifest68 совпал до/после и перед коммитом. [Evidence](../planning/history.md#результат-mp27-project-auth-policy--25-октября-2026). Это локальная приёмка блока; полная production assembly/public-ready/fleet этим не подтверждены.


MP5.1e: [dynamic readiness contract](project-settings-readiness.md) подключает фактический per-target source при включённом project HTTP; его tests/status отдельны. Старое описание закрытых capabilities относится к HTTP-disabled/историческому bridge, а не к готовому source.
