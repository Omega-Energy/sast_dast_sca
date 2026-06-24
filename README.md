# Security Platform

Единая платформа безопасности для автоматизированного анализа кода, бинарей и инфраструктуры. Развёртывается на выделенном виртуальном сервере с Docker-контейнерами.

## Архитектура

```
security-platform/
├── trust-gateway/               # Центральный портал управления
│   ├── portal-ui/               # Web UI (React, Vite, TailwindCSS)
│   ├── api/                     # REST/WebSocket API (FastAPI)
│   ├── workers/                 # Async workers (Celery/RQ)
│   ├── connectors/              # GitLab, SonarQube, Cuckoo, AssemblyLine
│   └── trustctl-cli/            # CLI-инструмент
│
├── devsecops-ci-templates/      # CI/CD шаблоны для GitLab
│   ├── secure-source.yml        # SAST + secrets
│   ├── secure-build.yml         # SBOM + signing
│   ├── secure-release.yml       # DAST + compliance
│   └── binary-artifact.yml      # Binary analysis
│
├── security-policy-as-code/     # Правила и политики
│   ├── semgrep-rules/           # Кастомные Semgrep правила
│   ├── yara-rules/              # YARA для бинарного анализа
│   ├── opa-policies/            # OPA/Rego (release gates, access)
│   ├── checkov-rules/           # IaC security
│   ├── gitleaks-rules/          # Детекция секретов
│   └── risk-scoring/            # Модель скоринга рисков
│
├── scanner-images/              # Docker-образы сканеров
│   ├── source-scanner/          # Bandit + Semgrep + Gitleaks + pip-audit
│   ├── binary-static-scanner/   # YARA + static analysis
│   ├── unpacker/                # Распаковка/деобфускация
│   └── sbom-generator/          # Syft + CycloneDX
│
├── assemblyline-custom-services/  # Сервисы для AssemblyLine
│   ├── company-yara/
│   ├── vendor-reputation/
│   └── internal-binary-policy/
│
└── infrastructure/              # Деплой и инфра
    ├── docker-compose/          # Compose для всех сервисов
    ├── ansible/                 # Настройка VPS
    ├── terraform/               # IaC (опционально)
    └── diagrams/                # Архитектурные схемы
```

## Интеграции

| Система | Роль |
|---------|------|
| **GitLab CI** | Запуск сканов в пайплайнах, webhooks |
| **SonarQube** | Импорт результатов анализа качества кода |
| **Cuckoo Sandbox** | Динамический анализ подозрительных файлов |
| **AssemblyLine** | Конвейер анализа бинарей |

## Инструменты безопасности

| Инструмент | Тип | Что проверяет |
|---|---|---|
| **Bandit** | SAST | Уязвимости в Python-коде |
| **Semgrep** | SAST + Secrets | Паттерны уязвимостей + секреты |
| **pip-audit** | SCA | CVE в зависимостях |
| **Gitleaks** | Secrets | Секреты в git-истории |
| **YARA** | Binary | Сигнатуры в бинарных файлах |
| **OPA** | Policy | Compliance и release gates |
| **Syft/Grype** | SBOM | Software Bill of Materials |

## Быстрый старт

```bash
# 1. Клонировать
git clone https://github.com/Omega-Energy/sast_dast_sca.git
cd sast_dast_sca

# 2. Запустить (legacy-дашборд)
docker compose up --build

# 3. Открыть
open http://localhost:8000
```

## Требования

- Docker + Docker Compose v2
- Git

## Legacy: SAST Dashboard

Текущий рабочий прототип находится в `backend/` и `frontend/` — SAST-дашборд для анализа Python-репозиториев с GitHub. Будет интегрирован в `trust-gateway/` на следующих этапах.
