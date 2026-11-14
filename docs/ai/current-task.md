# Текущий шаг

Первый U2 принят Luna и закоммичен как 12c4929d. [Контракт режимов](../features/settings-source.md).

Первый блок управляемой установки подготовлен и передан Luna. [Установка и восстановление комплекта](../operations/managed-install.md). Генератор создаёт приватный standalone комплект, разделяет owner/runtime credentials и использует текущий setup с SMTP и TOTP. Закрытая начальная policy применяется только при seed новой API-установки.

Снимок /private/tmp/auth-install-check-sCODdG/snapshot.tar.gz, SHA256 d2d32332f0904a7b28fb70a5bcdf5c77e4aa3b79208a05746da643e50af5d4e9. Проверка только delta. Luna переиспользует собственный стенд и сохраняет его для следующих прогонов. Финальная перепроверка PASS: тесты, pinned lint и путь Compose к миграциям. Снимок df4914b5726b345ab7a417b025a4c10d2530581cac91fc525cb34f6eac90eca6, отчёт /private/tmp/auth-install-recheck-ZfSGhn/receipt.json. Стенд auth-install-check-scod переиспользован и сохранён. Реальный SMTP и настройка первого владельца не проверялись. Следующий блок — политики U2. UI, миграция существующих установок и автоматическая ротация остаются последующими блоками.
