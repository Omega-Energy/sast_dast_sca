# DevSecOps CI Templates

Шаблоны CI/CD пайплайнов для интеграции безопасности в процесс разработки.

## Шаблоны

| Файл | Назначение |
|------|-----------|
| `secure-source.yml` | Проверка исходного кода: SAST + детекция секретов |
| `secure-build.yml` | Проверка сборки: SBOM генерация, подпись артефактов |
| `secure-release.yml` | Pre-release: DAST, compliance-проверки |
| `binary-artifact.yml` | Анализ бинарных артефактов перед публикацией |

## Использование (GitLab CI)

```yaml
include:
  - project: 'security/devsecops-ci-templates'
    file: '/secure-source.yml'

stages:
  - security-scan
```
