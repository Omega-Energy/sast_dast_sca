# Gitleaks Rules

Кастомные правила для детекции секретов в репозиториях.

## Что детектируем

- API-ключи корпоративных сервисов
- Внутренние токены и пароли
- Приватные ключи и сертификаты
- Connection strings к БД

## Формат (.toml)

```toml
[[rules]]
id = "company-internal-token"
description = "Internal service token"
regex = '''COMP_TOKEN_[A-Za-z0-9]{32}'''
tags = ["internal", "token"]
```
