# Внешние identities

## Реализовано в A3.1 / 7.1

`account` хранит владельца внешней identity в `auth.linked_identities`. Ключ — точная пара `issuer + subject`: регистр и содержимое не нормализуются, email не используется для поиска владельца. Один внутренний UUID может иметь несколько identities. UNIQUE/PK запрещает назначить одну identity двум пользователям; индекс user_id поддерживает операции владельца и FK. Сейчас нет публичной ручки добавления/удаления привязки.

`IdentityResolution.Resolve` принимает ключ **только после проверки доказательства методом входа**. Проверка формы ключа не проверяет подпись, issuer trust, audience, nonce или state: это обязанности будущего adapter. Нельзя принимать issuer/subject из произвольного клиентского JSON. Provider/client policy проверяется методом перед resolver, разрешение регистрации передаётся сервером, не браузером.

Resolver возвращает существующий active account и текущий auth_version. При неизвестной identity и запрещённой регистрации — ErrIdentityNotFound. При разрешённой регистрации user, identity и пустой profile создаются одной транзакцией, без выдуманного email/пароля и без переноса чужих прав. Конкурентный UNIQUE conflict откатывает весь проигравший candidate user, затем читает committed owner. Другие SQL ошибки не маскируются под duplicate и не повторяются автоматически.

В service один deadline 5 секунд для всего resolution. Штатный existing-user путь — один индексированный SELECT с JOIN users; создание — lookup и четыре INSERT (user/identity/profile/audit) в одной транзакции после A3.2. Нет Redis cache, обновления last-login на каждом входе, advisory locks, очереди или background worker. Сроки и суммарная concurrency ограничиваются существующими HTTP/DB budgets; этот модуль сам по себе не измеряет RPS.

## Совместимость и границы

Password/contact/session tables и их публичные APIs не меняются. External-only user может не иметь email и password credentials. Identity не доказывает verified contact; email от provider нельзя использовать для auto-merge. Resolver не выдаёт сессию: её создание позднее повторно проверяет status/auth_version через существующий SQL ledger, а MFA будет выполняться до выдачи session.

Pending/blocked/deleted account не получает успешный resolution. Блокировка/разблокировка сохраняет ownership; soft deletion сохраняет identity как reservation у tombstone, чтобы следующий callback не создал новый доступ в обход отзыва. Это не полное удаление персональных данных. Автоматический release identities сейчас отсутствует; отдельную политику release/PII erasure и защиты от takeover нужно согласовать до self-service deletion UI.

A3.2 подключает resolver к optional Telegram login с trusted OIDC verification, enabled/registration policy и transactional creation audit. Доступ к audit API, linking/unlinking и MFA orchestration ещё не реализован. Link/unlink потребует fresh auth и owner/session guards; автоматическое назначение identity существующему аккаунту отсутствует. [Telegram contract](telegram-login.md).

Схема добавлена в исходную 000001 согласно текущему pre-release правилу. Уже применённая БД не обновится повторным migrate up; нужен согласованный upgrade, не reset рабочей БД.

## Проверки

Unit tests: bounds 512/255 байт, пустые/некорректные ключи, сохранение opaque key, policy/deadline, inactive account и dependency failure. Disposable SQL: 16 concurrent resolutions дают один UUID без orphan users, disabled registration допускает только existing identity, issuer/subject case isolation, отсутствие email/password, rollback по SQL constraint, block/unblock/current version и deletion без повторного создания.

Внешний provider login и browser/fault/load acceptance здесь не выполняются. Linking, MFA, роли и UI остаются следующими подэтапами плана.
