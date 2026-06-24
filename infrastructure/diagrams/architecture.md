# Security Platform — Architecture

## High-Level Overview

```mermaid
graph TB
    subgraph External["External Systems"]
        GL[GitLab]
        SQ[SonarQube]
        CK[Cuckoo Sandbox]
        AL[AssemblyLine]
    end

    subgraph VPS["Dedicated VPS (Docker)"]
        subgraph Gateway["Trust Gateway"]
            UI[Portal UI<br/>React + Vite]
            API[REST/WS API<br/>FastAPI]
            W[Celery Workers]
            CON[Connectors]
        end

        subgraph Data["Data Layer"]
            PG[(PostgreSQL)]
            RD[(Redis)]
        end

        subgraph Scanners["Scanner Images"]
            SS[Source Scanner<br/>Bandit+Semgrep+Gitleaks]
            BS[Binary Scanner<br/>YARA+PE Analysis]
            UP[Unpacker<br/>UPX+XOR+Archives]
            SBOM[SBOM Generator<br/>Syft+Grype]
        end

        NX[Nginx Reverse Proxy]
        FL[Flower<br/>Task Monitor]
    end

    subgraph Users["Users"]
        DEV[Developers]
        SEC[Security Team]
        CLI[trustctl CLI]
    end

    DEV -->|browser| NX
    SEC -->|browser| NX
    CLI -->|HTTP| NX

    NX --> UI
    NX --> API

    API --> PG
    API --> RD
    API --> W

    W --> SS
    W --> BS
    W --> UP
    W --> SBOM
    W --> RD

    CON --> GL
    CON --> SQ
    CON --> CK
    CON --> AL

    GL -->|webhook| API
```

## Data Flow — Scan Pipeline

```mermaid
sequenceDiagram
    participant U as User/GitLab
    participant API as API Server
    participant R as Redis
    participant W as Celery Worker
    participant S as Scanner Container
    participant DB as PostgreSQL

    U->>API: POST /api/scans (or webhook)
    API->>DB: Create Scan record (status=pending)
    API->>R: Enqueue scan task
    API-->>U: 201 {scan_id}

    R->>W: Dequeue task
    W->>DB: Update status=running
    W->>S: Run scanner container
    S-->>W: JSON results
    W->>DB: Store results, update counts
    W->>DB: Update status=done
    W->>R: Publish completion event

    U->>API: GET /api/scans/{id}/results
    API->>DB: Fetch results
    API-->>U: 200 {findings...}
```

## Security Policy Flow

```mermaid
graph LR
    subgraph Policies["Security Policy as Code"]
        SG[Semgrep Rules]
        YR[YARA Rules]
        GL[Gitleaks Rules]
        OPA[OPA Policies]
        CK[Checkov Rules]
        RS[Risk Scoring]
    end

    subgraph Scanners["Scanner Images"]
        SS[Source Scanner]
        BS[Binary Scanner]
    end

    subgraph Gates["Release Gates"]
        RG[Release Gate<br/>OPA Rego]
        CP[Compliance Check]
    end

    SG --> SS
    GL --> SS
    YR --> BS
    CK --> |IaC validation| Gates

    SS --> RS
    BS --> RS
    RS --> RG
    RS --> CP

    RG -->|allow/deny| Deploy[Deploy Pipeline]
```

## Infrastructure

```mermaid
graph TB
    subgraph Cloud["Yandex Cloud"]
        subgraph VPC["VPC 10.10.0.0/24"]
            VM[VM: 4 vCPU / 8 GB RAM / 80 GB SSD]
        end
        DNS[Cloud DNS]
        SG[Security Group<br/>22, 80, 443]
    end

    Internet[Internet] -->|HTTPS| SG
    SG --> VM
    DNS --> VM

    subgraph VM_Internal["VM Services"]
        D[Docker Engine]
        D --> API[API Container]
        D --> Worker[Worker Container]
        D --> PG[PostgreSQL Container]
        D --> Redis[Redis Container]
        D --> Nginx[Nginx Container]
    end
```

## Port Mapping

| Service | Internal Port | External Port | Access |
|---------|--------------|---------------|--------|
| Nginx | 80/443 | 80/443 | Public |
| API | 8000 | - | Via Nginx |
| PostgreSQL | 5432 | 127.0.0.1:5432 | Local only |
| Redis | 6379 | 127.0.0.1:6379 | Local only |
| Flower | 5555 | 127.0.0.1:5555 | Local only |
