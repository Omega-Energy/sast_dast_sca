# Security Policy as Code

Централизованное хранилище правил и политик безопасности.

## Модули

| Директория | Назначение |
|-----------|-----------|
| `semgrep-rules/` | Кастомные правила Semgrep (SAST) |
| `yara-rules/` | YARA-правила для бинарного анализа |
| `opa-policies/` | OPA/Rego — политики доступа и compliance |
| `checkov-rules/` | Checkov — проверка IaC (Terraform, Docker) |
| `gitleaks-rules/` | Кастомные правила детекции секретов |
| `risk-scoring/` | Модель скоринга и приоритизации рисков |

## Принципы

- Все правила версионируются в Git
- CI валидирует синтаксис правил при каждом MR
- Правила тегируются по severity: CRITICAL / HIGH / MEDIUM / LOW
