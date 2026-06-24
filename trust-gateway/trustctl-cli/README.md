# trustctl CLI

Консольный инструмент для управления платформой безопасности.

## Стек

- Python (Typer)

## Планируемые команды

```bash
trustctl scan run --repo <url>        # Запустить скан
trustctl scan status <id>             # Статус скана
trustctl projects list                # Список проектов
trustctl connectors test <name>       # Проверить коннектор
trustctl policies validate            # Валидация политик
trustctl report generate <scan-id>    # Сгенерировать отчёт
```
