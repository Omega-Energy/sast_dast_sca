# Source Scanner

Docker-образ для комплексного анализа исходного кода.

## Включённые инструменты

- **Bandit** — SAST для Python
- **Semgrep** — мультиязычный SAST + секреты
- **Gitleaks** — детекция секретов в git-истории
- **pip-audit** — SCA для Python-зависимостей

## Использование

```bash
docker run --rm -v $(pwd):/src source-scanner /src
```
