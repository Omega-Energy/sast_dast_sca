# Ansible

Playbooks для первоначальной настройки и обслуживания VPS.

## Playbooks

| Playbook | Назначение |
|----------|-----------|
| `setup.yml` | Установка Docker, настройка firewall, создание пользователей |
| `deploy.yml` | Деплой/обновление платформы |
| `backup.yml` | Бэкап данных и конфигураций |

## Использование

```bash
ansible-playbook -i inventory setup.yml
```
