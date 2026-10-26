# Смена пароля и повторное подтверждение в проекте

MP5.1g, 26 октября 2026. Проектные HTTP bindings реализованы, локальные проверки Luna V1/V2 PASS. Это часть account management, не весь MP5 и не начало UI.

## API

Обе ручки доступны на точном HTTPS origin выбранного проекта при готовом browser password profile. Они требуют `__Host-session` и точный Origin, используют `NoRefreshAuth`. Проект выбирает существующая TLS/Host/runtime boundary; пользователь и текущий token hash берутся из проверенной cookie.

| POST | JSON | Результат |
| --- | --- | --- |
| `/api/v1/auth/reauthenticate/password` | `password` | 200, `validUntil`; новая cookie вместо прежней |
| `/api/v1/auth/change-password` | `oldPassword`, `newPassword`, `confirmPassword` | 200, прежний контракт `{"Status":"ok"}`; cookie очищается |

Повторное подтверждение проверяет пароль, затем SQL связывает результат с актуальными password hash, auth_version и действующей browser session. Токен заменяется атомарно, `password_verified_at` обновляется для этой сессии; session UUID, сроки, primary/MFA proof и permissions не меняются. Старый токен сразу перестаёт работать. Ответ не содержит пароль или токен в JSON. При потере успешного ответа нужен новый вход; запросы вокруг замены cookie следует выполнять последовательно.

Смена пароля сохраняет существующее требование подтверждённого login email, даже если SMTP сейчас не настроен. Подтверждение берётся из SQL, не из input. Требуется старый пароль: недавняя reauthentication не заменяет его в этой ручке. Новый пароль проверяет существующая domain policy. SQL повторно проверяет активность пользователя, текущую сессию и ожидаемый password hash, меняет hash, увеличивает auth_version, отзывает сессии и пишет audit в одной транзакции. После успеха нужно войти заново. Состояние MFA и роли не сбрасываются.

Оба проектных сценария ограничены существующим scoped Redis LoginLimit: user/IP/project budgets. Смена пароля проверяет бюджет после формы JSON, до хеширования. Используется `httpx.IP` после общего proxy/client-IP middleware. При исчерпании — 429 с Retry-After, при отказе Redis — 503 без выполнения смены пароля. Bounded hasher общий для процесса, ослабления Argon2 нет.

При отключении SQL password method или browser deployment новые ручки не монтируются. Управление существующими сессиями остаётся доступным по отдельному [контракту](project-session-management.md). При required email verification и неготовой verification capability password profile остаётся закрытым по прежним правилам; этот блок их не обходит.

## Сборка

`ProjectPassword.ChangePassword` и `ConfirmReauthentication` используют существующие password/session services и repositories. Каждая операция получает один scoped `Registry.UsePool`, ограничена project timeout и проверяет catalog key до/после; вложенных leases нет. Репозитории не сохраняются, SQL connection не удерживается во время hash. Финальный key guard скрывает результат устаревшего проекта, но не обещает отката уже завершённой транзакции.

Узкий `ChangePasswordHandler` принимает только нужный сервис и attempt limiter; общий `PasswordHandler` сохраняет прежний constructor/interface и включает этот handler. HTTP DTO/Swagger остаются рядом с ручкой; error mapper один для password feature. Legacy constructor сохраняет прежнее поведение; scoped attempt limit явно передаёт project assembly. Новых SQL schema, ENV, библиотек, pools или workers нет.

## Проверки и оставшиеся границы

Добавлены HTTP tests, что rate limit/Redis failure останавливают обработку до password service. Actual HTTPS/SQL fixture проверяет Origin/session guards, ошибочный и верный пароль, смену cookie при reauth, сохранение сроков/MFA, verified-email отказ без SMTP, mismatch/неверный старый пароль, auth_version increment, отзыв нескольких сессий и новый вход. Отключённый password profile не публикует эти ручки. Изменённые synthetic hash/contact и точные Redis keys восстанавливаются/очищаются fixture.

Main выполнил formatter, Swagger generation и source review. Luna V1: task check/API/security/affected race/runtime assembly/operator SQL PASS. В full command SQL исправлено единственное неверное ожидание теста: wrong-password login возвращает существующий 400, не 401. V2 targeted lint и полный Linux ARM64 TestPrepareCommandSQL PASS, project HTTP profile выполнен без skips. Все 11 source hashes и Swagger JSON/YAML совпали с main; собственный стенд очищен. Snapshot/evidence — в history. Account/identity/MFA management, полная двухпроектная приёмка, эксплуатация и финальная нагрузка остаются отдельными этапами.
