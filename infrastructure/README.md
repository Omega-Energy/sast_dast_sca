# Infrastructure

Инфраструктурный код для развёртывания платформы на выделенном VPS.

## Компоненты

| Директория | Назначение |
|-----------|-----------|
| `docker-compose/` | Compose-файлы для всех сервисов платформы |
| `ansible/` | Playbooks для настройки VPS (Docker, firewall, мониторинг) |
| `terraform/` | IaC для создания VM (опционально) |
| `diagrams/` | Архитектурные диаграммы |

## Быстрый деплой

```bash
# 1. Настроить VPS
cd ansible && ansible-playbook -i inventory setup.yml

# 2. Запустить платформу
cd docker-compose && docker compose up -d
```
