# Binary Static Scanner

Docker-образ для статического анализа бинарных файлов.

## Включённые инструменты

- **YARA** — сигнатурный анализ
- **strings** — извлечение строк
- **file** — определение типа файла
- **objdump** — дизассемблирование
- **radare2** — продвинутый анализ (опционально)

## Использование

```bash
docker run --rm -v $(pwd)/artifacts:/scan binary-static-scanner /scan
```
