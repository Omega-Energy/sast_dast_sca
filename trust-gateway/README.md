# Trust Gateway

Центральный компонент платформы — портал управления безопасностью.

## Подмодули

| Модуль | Назначение |
|--------|-----------|
| `portal-ui/` | Web-интерфейс (React, Vite, TailwindCSS) |
| `api/` | REST/WebSocket API (FastAPI) |
| `workers/` | Асинхронные воркеры для запуска сканов (Celery/RQ) |
| `connectors/` | Интеграции с внешними системами (GitLab, SonarQube, Cuckoo) |
| `trustctl-cli/` | CLI-инструмент для управления платформой |

## Запуск (dev)

```bash
docker compose up --build
```
