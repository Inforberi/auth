# Управление сессиями проекта

MP5.1f, 25 октября 2026. Реализовано подключение существующих session handlers/services к проектному runtime. Локальные проверки Luna V1/V2 PASS; полная двухпроектная приёмка и UI остаются отдельными этапами.

## Маршруты

Все пути ниже находятся под `/api/v1/auth` на точном HTTPS origin проекта. Cookie — существующая `__Host-session`, Secure, HttpOnly, Path=/, без Domain. Идентификаторы пользователя и сессии берутся из проверенной cookie, а проект — из доверенного runtime context, не из тела запроса.

| Метод и путь | Результат | Защита сессии |
| --- | --- | --- |
| GET `/me` | Идентификаторы текущих пользователя и сессии | Auth |
| GET `/sessions?before=<UUID>` | Собственные активные browser/API сессии, до 50 за страницу, `nextCursor` | Auth |
| POST `/logout` | Отзыв текущей сессии, очистка cookie, 204 | LogoutAuth |
| POST `/logout-all` | Отзыв всех сессий пользователя и увеличение `auth_version`, очистка cookie, 204 | NoRefreshAuth |
| DELETE `/sessions/{id}` | Отзыв выбранной собственной сессии, 204; для текущей также очистка cookie | NoRefreshAuth |
| POST `/session/activity` | Ограниченное продление административного idle-окна при взаимодействии пользователя | NoRefreshAuth |
| POST `/session/rotate` | Замена текущего cookie-токена, 204 | NoRefreshAuth |

GET использует прежнюю политику Auth: обычная сессия может продлеваться в пределах абсолютного срока. Activity не продлевает обычную сессию; для административной SQL объединяет частые сигналы в сохранённый интервал. Polling не следует выдавать за взаимодействие пользователя.

Изменяющие операции требуют точного Origin проекта; GET без Origin разрешён, чужой Origin отклоняется. CORS не включён. Управление требует действующей browser-сессии; native bearer credential не заменяет её. SQL повторно проверяет пользователя, актуальную auth_version, принадлежность caller и сроки. Новых требований fresh-auth/MFA здесь нет: отзыв собственной сессии не должен блокироваться дополнительным фактором. Существующие ограничения роли/MFA сохраняются через `auth.role_bound_sessions`.

Ротация не меняет session UUID, срок или доказательства входа/MFA. Старый токен сразу недействителен; один конкурентный запрос выигрывает, проигравший не очищает новую cookie. При потере успешного ответа потребуется новый вход. Отдельный отзыв не раскрывает чужие/неизвестные/неактивные сессии: одинаковый 404. Неверный UUID/cursor — 400. Logout с невалидной cookie возвращает 401 и очищает её; сбой зависимостей не считается успешным logout.

## Включение и владение

Маршруты включаются при `browser=true` в доверенном deployment source. Отключение отдельных SQL login methods не убирает управление уже выданными сессиями. При отсутствии активного browser login компонента используется проверенный `ProjectHTTPConfig.SessionValidation`; неверная/отсутствующая необходимая конфигурация не публикует профиль. При `browser=false` этих семи маршрутов нет; session-protected JWT exchange сохраняет собственный guard.

`projectHTTPSessions` связывает HTTP с прежними сервисами, не копируя DTO, SQL, ошибки или бизнес-правила. Каждая операция получает scoped repository внутри одного `Registry.UsePool`, ограничена deadline 5 секунд и проверяет текущий catalog key до и после. Middleware validation и операция последовательны: вложенных leases нет. Репозиторий/пул не сохраняются за пределами callback. Проверка key после записи не обещает откат уже завершённой SQL транзакции.

Списки ограничены и используют существующий cursor. Новых pools, workers, Redis keys, ENV, SQL schema или зависимостей нет. Suspend/stale policy по-прежнему проверяются boundary/dispatcher до handler. Авторизация не кешируется в resident profile.

## Приёмка

Добавлены route guard/closed configuration cases и расширен существующий HTTPS/SQL fixture: `/me`, список, неверный cursor, отзыв, повторный отзыв, activity, Origin, ротация, logout, logout-all, доступ после отключения login. Luna V1: API/security/targeted race/runtime assembly/operator SQL PASS; task check остановлен замечаниями линтера, command SQL — устаревшими ожиданиями числа маршрутов. Замечания исправлены. Luna V2: task check/router race/full Linux ARM64 TestPrepareCommandSQL PASS, новый session HTTP fixture выполнен без skips. Все 14 source hashes совпали после cleanup и с рабочим деревом. Собственный стенд очищен; детали снимка и evidence — в history.

Account/identity/MFA management, полная cross-project матрица, operational drills и нагрузка остаются отдельными задачами. Этот блок не закрывает весь MP5 и не начинает UI.

31 октября принят `TestTwoProjectSessionLifecycleIsolationSQL`: реальные HTTPS profiles A/B, чужие cookies/session IDs, list/revoke/rotate/logout/logout-all и block/unblock/delete A при сохранении B. Admin proof получают через существующий password reauthentication API; MFA policy optional. Luna V2 targeted lint/race, manifest14 и cleanup PASS; V1 task check PASS, ошибочное fixture ожидание401 исправлено на контрактное400. [Достаточные проверки и границы](../planning/multi-project.md#сессии-и-почта-двух-проектов--mp5-sessions-email). Прежний single-project PASS не считается результатом этого снимка.
