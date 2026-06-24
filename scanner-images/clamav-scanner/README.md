# ClamAV Scanner

Антивирусный сканер проектных файлов на базе ClamAV. Обнаруживает вирусы, трояны, бэкдоры, майнеры и другое вредоносное ПО в файлах репозитория.

## Возможности

- Рекурсивное сканирование директорий
- Два режима: `local` (clamscan CLI) и `daemon` (clamd через сеть — быстрее)
- Классификация угроз по severity (CRITICAL/HIGH/MEDIUM/LOW)
- JSON-отчёт, совместимый с платформой
- Фильтрация по размеру и типу файла

## Запуск

```bash
# Собрать образ
docker build -t security/clamav-scanner .

# Сканировать директорию (local mode)
docker run --rm -v /path/to/project:/scan security/clamav-scanner /scan

# С clamd демоном
docker run --rm -v /path/to/project:/scan security/clamav-scanner /scan --mode daemon --clamd-host clamav

# Сохранить отчёт
docker run --rm -v /path/to/project:/scan -v /tmp:/output security/clamav-scanner /scan -o /output/clamav_report.json
```

## Классификация угроз

| Severity | Типы |
|----------|------|
| CRITICAL | Trojan, Backdoor, Rootkit, Ransomware, Exploit |
| HIGH | Virus, Worm, Miner, Keylogger, Stealer |
| MEDIUM | Adware, PUP, Heuristic, Suspicious |
| LOW | Phishing, Spam, Test signatures |
