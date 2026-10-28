# Danielle Respes

![Focus](https://img.shields.io/badge/Focus-Alert%20Triage%20%26%20Identity%20Response-0e5a8a)
![Tools](https://img.shields.io/badge/Tools-Sentinel%20%7C%20KQL%20%7C%20Defender%20%7C%20Entra%20ID-6f42c1)
![Security+](https://img.shields.io/badge/CompTIA%20Security%2B-Expected%20Nov%202026-2ea44f)

Applying endpoint and identity investigation with Microsoft Defender, Microsoft Sentinel, Entra ID, and KQL to triage alerts, separate real threats from false positives, and respond to compromised accounts.

> [!NOTE]
> Learning KQL and Defender is not required by my current role. I do this work on my own to build deeper cybersecurity skills beyond help desk responsibilities.

## Triage Process

```mermaid
flowchart TD
    A["1. Intake<br/>Alert source, severity, identity, device"]:::step --> B["2. Context Checks<br/>Sign-in location, MFA, device OS, password history"]:::step
    B --> C{"3. False Positive?<br/>Installer, VPN, travel"}:::decision
    C -->|Yes| F["Document as benign"]:::done
    C -->|No| D{"4. Containment Needed?"}:::decision
    D -->|Suspicious sign-in| E["Reset password<br/>Enforce MFA"]:::action
    D -->|Evidence of compromise| G["Isolate endpoint<br/>Reimage with IT approval<br/>Escalate to supervisor"]:::action
    E --> H["5. Investigate<br/>Sentinel timeline with KQL"]:::step
    G --> H
    H --> I["6. Document<br/>Timeline, actions, outcome, follow-up"]:::step
    I --> J["7. Lessons Learned<br/>Detection or policy recommendations"]:::done

    classDef step fill:#e6f1f8,stroke:#0e5a8a,color:#0f172a
    classDef decision fill:#fef3c7,stroke:#d97706,color:#0f172a
    classDef action fill:#fee2e2,stroke:#b91c1c,color:#0f172a
    classDef done fill:#dcfce7,stroke:#16a34a,color:#0f172a
```

Account disables and reimaging require supervisor or IT leadership approval. A disabled account stays locked until staff reactivate it.

## Core Tools

Microsoft Sentinel · KQL · Defender for Endpoint · Defender XDR · Entra ID · Microsoft 365 · Intune · MITRE ATT&CK · NIST 800-61

## Skills

- Alert triage and false-positive analysis
- KQL queries across Defender and Entra sign-in and endpoint data
- Identity response: password reset, MFA enforcement, sign-in risk review
- Endpoint containment and reimaging with IT leadership
- Clear documentation for supervisors and account owners
- Collaboration with IT leadership and senior staff on containment, reimaging, and user communication decisions



## Lab Work


| Project | Summary |
|---|---|
| [Northpeak Descent Cross-Platform Intrusion Investigation](https://github.com/Danielle-Respes/Northpeak-Descent-Cross-Platform-Intrusion-Sentinel-KQL-2026) | Lab investigation across Windows and Linux telemetry in Defender for Endpoint and Sentinel, using KQL to reconstruct the intrusion sequence and separate real logon activity from noise. |
| [Copilot Prompt-Injection Threat Hunt (EchoLeak)](https://github.com/Danielle-Respes/Threat-Hunt-EchoLeak-Copilot-Prompt-Injection-Sentinel-KQL-Oct-2026) | Simulated M365 Copilot data. Traced an attack path and exfiltration channel in Sentinel, and documented log gaps. |
| [Vulnerability Management Program](https://github.com/Danielle-Respes/Vulnerability-Management) | Tenable scanning in Azure VMs, CVSS prioritization, and a mock Change Advisory Board review. |

## Contact

github.com/Danielle-Respes
