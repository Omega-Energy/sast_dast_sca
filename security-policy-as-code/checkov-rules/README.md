# Checkov Rules

Кастомные правила Checkov для проверки Infrastructure-as-Code.

## Что проверяем

- Dockerfile — best practices (no root, multi-stage, pinned versions)
- Docker Compose — безопасная конфигурация
- Terraform — security groups, encryption, IAM
- Kubernetes manifests — pod security

## Формат

Правила в формате Python (custom checks) или YAML (simple policies).
