# Semgrep Rules

Кастомные правила Semgrep для обнаружения уязвимостей в исходном коде.

## Структура

```
semgrep-rules/
├── python/          # Правила для Python
├── javascript/      # Правила для JS/TS
├── go/              # Правила для Go
└── generic/         # Языконезависимые паттерны
```

## Формат правила

```yaml
rules:
  - id: company-sql-injection
    patterns:
      - pattern: cursor.execute($QUERY)
      - pattern-not: cursor.execute($QUERY, $PARAMS)
    message: "SQL injection risk: use parameterized queries"
    severity: ERROR
    languages: [python]
```
