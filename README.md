# 🔐 SAST Security Dashboard

Веб-дашборд для автоматизированного анализа безопасности Python-репозиториев с GitHub.

## Инструменты

| Инструмент | Тип | Что проверяет |
|---|---|---|
| **Bandit** | SAST | Уязвимости в Python-коде (SQLi, XSS, hardcoded secrets и др.) |
| **Semgrep** | SAST + Secrets | Паттерны уязвимостей + утечки секретов в коде |
| **pip-audit** | SCA | CVE в зависимостях из `requirements*.txt` / `pyproject.toml` |
| **Gitleaks** | Secrets | Секреты (API keys, токены, пароли) в истории git |

## Требования

- Docker + Docker Compose v2

## Быстрый старт

```bash
# Собрать и запустить
docker compose up --build

# Открыть дашборд в браузере
start http://localhost:8000
```

## Возможности дашборда

| Страница | Описание |
|---|---|
| **Dashboard** | Сводная статистика + график findings по сканам |
| **New Scan** | Запуск скана с live-логом через WebSocket |
| **History** | Таблица всех сканов со статусом и счётчиками |
| **Compare** | Side-by-side сравнение двух сканов, новые findings |
| **Scan Detail** | Таблицы findings с фильтрацией по severity/тексту + скачать JSON |

## Приватные репозитории

Вставь GitHub Personal Access Token (scope: `repo`) в поле **GitHub Token** в форме запуска.

## Структура проекта

```
.
├── docker-compose.yml          # Оркестрация
├── backend/
│   ├── Dockerfile.full         # Multi-stage: Node.js build + Python + tools
│   ├── main.py                 # FastAPI + WebSocket + SQLite
│   ├── scanner.py              # Логика запуска инструментов
│   ├── models.py               # SQLModel схема БД
│   ├── requirements.txt
│   └── data/                   # SQLite БД (создаётся автоматически)
├── frontend/
│   ├── src/
│   │   ├── pages/              # Dashboard, NewScan, ScanDetail, History, Compare
│   │   ├── components/         # StatCard, Badge
│   │   └── api.ts              # REST + WebSocket клиент
│   └── package.json
└── reports/                    # JSON-результаты сканов
```

## API

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/api/scans` | Запустить новый скан |
| `GET` | `/api/scans` | Список всех сканов |
| `GET` | `/api/scans/{id}` | Статус скана |
| `GET` | `/api/scans/{id}/results` | Результаты (JSON) |
| `DELETE` | `/api/scans/{id}` | Удалить скан |
| `GET` | `/api/stats` | Агрегированная статистика |
| `WS` | `/ws/scans/{id}/log` | Live-лог выполнения |
