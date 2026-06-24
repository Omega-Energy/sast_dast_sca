# OPA Policies

Политики на языке Rego для Open Policy Agent.

## Назначение

- **Release gate** — блокировка релиза при наличии CRITICAL/HIGH уязвимостей
- **Access control** — контроль доступа к ресурсам платформы
- **Compliance** — проверка соответствия стандартам (PCI DSS, ISO 27001)

## Пример

```rego
package release

default allow = false

allow {
    input.critical_count == 0
    input.high_count <= 3
    input.scan_age_hours < 24
}
```
