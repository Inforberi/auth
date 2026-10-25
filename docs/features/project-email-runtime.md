# Проектные email-сценарии и доставка

MP4.1e,25 октября2026. Решение перед реализацией.

- Переиспользовать account verification и password recovery services/repositories, scoped Redis/ciphers и сохранённый project SMTP. Не копировать issuance/consume/claim/retry SQL и не создавать новые очереди/schema/dependencies.
- URL подтверждения/reset задаёт trusted assembly для конкретного HTTPS origin проекта; не принимать их из публичного request/Host, не наследовать platform ENV. Пока нет project host routing, новые HTTP routes/readiness не публикуются.
- Операция использует одну UsePool lease, request-local repositories/services. Mail source читает тот же pool внутри callback; повторного захвата registry нет. Во время hashing/SMTP физическое SQL-соединение не удерживается. Completion использует existing bounded WithoutCancel cleanup.
- Guard текущего key до/после операции и перед SMTP; suspend/stale snapshot запрещает новую отправку. Уже начатый внешний SMTP side effect мгновенно отменить нельзя. Existing SQL30s claim /20s SMTP/5 retries сохраняются, exactly-once не обещается.
- Фоновый обход готовых enabled проектов — bounded keyset pages private reader, независимо от HTTP/resident traffic. Один runner на процесс, ограниченный parallelism и page size, одна verification/reset попытка за очередь на проект за проход; без workers/горутин на каждый зарегистрированный проект и без удержания полного каталога в памяти. Shared pools/dependencies принадлежат процессу. Не включать runner автоматически до согласованной operational/lifecycle сборки и бюджета по экземплярам.
- В этом блоке только verification и password reset; приглашения/change/binding/OTP/MFA delivery подключаются отдельно с явными prerequisites.
- До завершения: formatter/diff; Luna — task check, affected race, actual SQL+Redis issuance/consume/project scope/retry/lease/cancel/suspend/selection и scheduler bounds/shutdown. Проверки на immutable snapshot; source в проверяющем чате не меняется.

## Реализация

`internal/app/auth/project_email.go` — NewProjectEmail и ResendVerification/ConfirmVerification/ForgotPassword/ResetPassword. Project data key заменяет любой переданный outbox key; cipher purposes и Redis keys изолированы существующим realm scope. Проверка recovery config перенесена из общей config в существующий password Config.Validate и вызывается обоими потребителями, без второго набора правил. Email URL должны принадлежать явно переданному HTTPS origin; это assembly input, не HTTP Host. Ошибка финальной сверки после commit не доказывает rollback уже выполненной операции.

`project_email_runtime.go` — построение services только внутри lease, без копирования business/SQL логики. В delivery path URL/hash не используются: ciphertext уже содержит готовое письмо. SMTP source получает текущий borrowed pool, ограничивает чтение3s и проверяет key; вложенной registry lease нет. Внешняя операция может пережить suspend после последней проверки; следующий вызов запрещён.

`project_delivery.go` — opt-in NewProjectDelivery/Run, PageSize/Parallelism в пределах existing StateBatchSize, interval1s–1m. Один bounded набор workers на страницу, не на каждый проект. Пустая завершающая страница сбрасывает cursor; ошибка выборки сохраняет cursor и повторяется после interval. Сборка и отправка проекта освобождают lease после операции, SQL connection во время SMTP не удерживается. Missing/invalid SMTP проверяется до claim. Verification/reset получают по одному проходу, existing SQL retry/lease/expiry/attempt caps не менялись. Report вызывается последовательно после drain страницы; caller не должен его блокировать. Отмена прекращает новую выдачу и ждёт bounded текущие operations/cleanup.

`RuntimeCredentialReader.PageRuntimes` использует private reader profile, exact snapshot predicate и descending(created_at,id) cursor. В памяти одна ограниченная страница; неполный/malformed candidate пропускается с продвижением cursor. Секреты в выборке не возвращаются; consumer снова проверяет binding. В initial catalog schema добавлен partial index для ready/enabled обхода. Новая миграция/изменение рабочей БД не выполнялись; существующим installations понадобится controlled upgrade.

## Текущие ограничения

Это внутренние assembly API. [MP4.1f](project-delivery-lifecycle.md) добавляет default-off включение runner в server lifecycle и operational concurrency budget; его verification gate отделён от проверок MP4.1e. Полные fleet fairness и MP4.4/4.5 ещё не закрыты. Доставка не зависит от HTTP-трафика при запущенном runner. HTTP/routing/readiness, registration assembly и остальные email очереди этим блоком не открываются. Успешная внешняя TLS-доставка не подтверждена SMTP mock без STARTTLS.

## Проверки

Добавлены unit tests trusted URLs, worker concurrency/fairness/cancellation и actual project SQL/Redis drill: issuance двух encrypted outbox, разные purposes, private-reader keyset selection без HTTP, worker safe TLS failure/retry, email confirm/reset+replay, новый password hash и suspend/selection exclusion. Luna V3: task check exit0/lint0, app/auth race exit0; V2 config/cmd race и actual full TestPrepareCommandSQL exit0 без SKIP. Manifest11 совпал до/после и с main; owned PostgreSQL/Redis cleanup подтверждён. После V2 изменён только тип счётчика scheduler, поэтому успешный SQL-прогон не повторялся. Evidence — history, snapshot `/private/tmp/auth-project-email-v3.5mpw8ae3`.
