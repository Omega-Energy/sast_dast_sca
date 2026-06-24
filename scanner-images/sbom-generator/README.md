# SBOM Generator

Docker-образ для генерации Software Bill of Materials.

## Включённые инструменты

- **Syft** — генерация SBOM (CycloneDX, SPDX)
- **Grype** — сканирование SBOM на уязвимости

## Форматы вывода

- CycloneDX JSON/XML
- SPDX JSON
- Syft native JSON

## Использование

```bash
docker run --rm -v $(pwd):/src sbom-generator syft /src -o cyclonedx-json
```
