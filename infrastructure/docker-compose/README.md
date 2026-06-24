# Docker Compose

Compose-файлы для развёртывания всех сервисов платформы одной командой.

## Сервисы

- **gateway-api** — FastAPI backend
- **gateway-ui** — React frontend (nginx)
- **workers** — Celery воркеры
- **redis** — брокер сообщений
- **postgres** — база данных (при масштабировании)

## Запуск

```bash
docker compose up -d
```
