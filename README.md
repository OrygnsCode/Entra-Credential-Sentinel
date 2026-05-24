# Entra Credential Sentinel (V3)

An enterprise-grade, deterministic, read-only Python tool to audit Microsoft Entra app registrations and service principals for credential hygiene and security risks.

## Features

- **Audit Scope**: Scans both **App Registrations** and **Enterprise Applications (Service Principals)**.
- **Credential Auditing**: Checks for expired and expiring client secrets, certificates, and federated credentials.
- **Orphaned Identity Detection**: Flags entities with no assigned owners (checks both local owners and `appOwnerOrganizationId`).
- **Risky Permission Analysis**:
  - Dynamically resolves permission names (e.g., `Directory.ReadWrite.All`).
  - Flags high-risk Application Permissions (e.g., `RoleManagement.ReadWrite.Directory`).
  - Flags high-risk Delegated Grants (only if the resource is Microsoft Graph).
- **Flexible Reporting**: Deterministic CSV and JSON output with rich details.

## Installation

```bash
# Clone the repository
git clone https://github.com/OrygnsCode/Entra-Credential-Sentinel.git
cd Entra-Credential-Sentinel

# Option A: Install directly (Recommended)
pip install .

# Option B: Editable install for development
pip install -e .
```

## Authentication & Setup

1. **Prerequisites**:
   - Python 3.10+
   - A Microsoft Entra ID Tenant
   - A Service Principal with the following **Application** permissions (Admin Consent Required):
     - `Application.Read.All` (To scan Apps)
     - `ServicePrincipal.Read.All` (To scan Service Principals)
     - `AppRoleAssignment.Read.All` (To analyze app roles)
     - `DelegatedPermissionGrant.Read.All` (To analyze delegated grants)
     - `Directory.Read.All` (Optional, for Owner Organization discovery)

2. **Configuration**:
   Create a `.env` file in the root directory (based on `.env.example`):
   ```ini
   TENANT_ID=your-tenant-id
   CLIENT_ID=your-client-id
   CLIENT_SECRET=your-client-secret
   # OPTIONAL:
   # LOG_LEVEL=INFO
   ```

> [!IMPORTANT]
> **Security:** Never commit your `.env` file or `out/` directory. This tool uses read-only permissions but handles sensitive data.

## Usage

Once installed, you can run the tool via the command line:

```bash
# View help
entra-credential-sentinel --help

# Standard Run (Apps & SPs, CSV & JSON)
entra-credential-sentinel --scope both --format both

# Filter Output (Only risky items)
entra-credential-sentinel --only-risky

# CI/CD Integration (Fail on risk)
entra-credential-sentinel --fail-on-risk --fail-on-expired
```

### Direct Execution
If you prefer not to install the package, you can run it directly:
```bash
python3 -m entra_sentinel --scope both
```

## CLI Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| `--scope` | Scan `apps`, `sps`, or `both` | `both` |
| `--expiry-window-days` | Days to flag expiring credentials | `30` |
| `--output-dir` | Directory for reports | `out` |
| `--only-risky` | Only output findings with issues | `False` |
| `--fail-on-risk` | Exit code 2 if risky perms found | `False` |
| `--fail-on-expired` | Exit code 2 if expired creds found | `False` |
| `--fail-on-orphaned` | Exit code 2 if orphaned found | `False` |

## Output

The tool generates reports in the `out/` directory (or specified via `--output-dir`):

- **entra_credential_sentinel.csv**: Flat file for easy analysis.
  - `NextExpiryInDays`: Days until the next credential expires.
  - `OwnerStatus`: `OWNED`, `ORPHANED`, `UNKNOWN_OWNER_ORG`, or `EXTERNAL_MANAGED`.
  - `RiskyPermCount`: Number of high-risk permissions detected.
- **entra_credential_sentinel.json**: Full hierarchical data.
  - Contains full permission details (`riskyPermissions` object).
  - Metadata includes tool version and scan summary.

## Limitations

- Does not modify or remediate any resources (Read-Only).
- "Risky" permissions are based on a curated list; custom risks can be added via `--risk-map-json`.
- Owner organization detection relies on `Directory.Read.All` for best accuracy; falls back to "Unknown" if permission is missing.

## License

Copyright (c) 2025 OrygnsCode.  
Licensed under the [MIT License](LICENSE).

---

Built by [Orygn](https://orygn.tech), custom software and security tooling for small businesses and growing teams.
