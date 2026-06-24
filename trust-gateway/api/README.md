# API

REST и WebSocket API платформы.

## Стек

- Python 3.11+
- FastAPI
- SQLModel + SQLite/PostgreSQL
- Pydantic v2

## Основные эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| POST | /api/scans | Запуск нового скана |
| GET | /api/scans | Список сканов |
| GET | /api/scans/{id}/results | Результаты скана |
| GET | /api/projects | Список проектов |
| POST | /api/connectors | Настройка коннектора |
| WS | /ws/scans/{id}/log | Live-лог сканирования |
