# Текущий шаг

4 ноября 2026. R6 завершён и принят: `/private/tmp/auth-r6-settings-token-v4-k_io6d07`, base `1bc286c`. Пользователь разрешил коммит после PASS; изменение включается в `refactor(auth): разделил настройки и обработчики токенов`. Актуальный hash/staging проверять Git.

Settings SMTP/providers/retention/Telegram Bot имеют service/HTTP, token native/introspection HTTP отделены. Общие Policy/MFA/domain/ports/parser, SQL transaction owners и token admission/signing/native authority сохранены. Публичные tests у владельцев, private security/codec/DTO/gate tests рядом. Архитектура и пути обновлены. Четыре settings SQL fixtures исправлены под действующие MFA constraints: отсутствие required proof запрещает read, stale proof допускает read и запрещает mutation. Production/schema/routes/ENV/dependencies не менялись.

Luna PASS: 38 affected packages race, pinned lint0, API, 11 exact SQL roots с11 selected JWT/native/refresh leaves, обе Redis suites. Main сверил source hashes и actual logs/receipts. [Evidence/ограничения](../operations/acceptance-summary.md#r6-настройки-и-http-токенов--приёмка-4-ноября-2026). Автоматическая проверка отклонила итоговую обратную отправку из Luna; main получил результат через read_thread и сверил evidence, повторять пройденные tests не нужно.

Следующий блок — [R7](../planning/readability-refactor.md#r7-завершение-сборки-приложения-и-lifecycle): завершение root app/admin/projects, оставшиеся wrappers/profile configuration и lifecycle. Сначала сверить уже сделанное R3–R6, не переносить повторно готовые adapters. Фичевые контракты не менять.

Все executable checks и стенд — Luna 01a16eab-c777-78a0-a815-47b45ff0860d. Собственный `auth-r5-retained` сохранён, данные очищены; metadata `/private/tmp/auth-r5-retained-fixture.json`, Compose `/private/tmp/auth-r5-retained-compose.yml`. Проверять совместимость/health и актуальную сборку, не трогать чужие ресурсы. В каждой передаче указывать main01a1084e-24bd-79f3-8c3a-769ffd8ec98a и обязательный tool report; при блокировке доставки main читает итог и evidence, молчание не PASS. R2 live/external/MP7/MP8 gates отдельно; UI без согласования не начинать.
