# Scanner Images

Docker-образы сканеров безопасности, оптимизированные для CI/CD.

## Образы

| Образ | Инструменты | Назначение |
|-------|-------------|-----------|
| `source-scanner` | Bandit, Semgrep, Gitleaks, pip-audit | SAST + секреты + SCA |
| `binary-static-scanner` | YARA, strings, file, objdump | Статический анализ бинарей |
| `unpacker` | unzip, 7z, upx, binwalk | Распаковка и деобфускация |
| `sbom-generator` | Syft, CycloneDX CLI | Генерация SBOM |

## Сборка

```bash
docker build -t source-scanner ./source-scanner/
docker build -t sbom-generator ./sbom-generator/
```
