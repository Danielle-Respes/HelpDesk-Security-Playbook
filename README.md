# Help Desk Security & Incident Triage Playbook

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active%20Portfolio-brightgreen?style=for-the-badge&logo=git&logoColor=white" alt="Status">
  <img src="https://img.shields.io/badge/Domain-IT%20Help%20Desk%20%7C%20Cybersecurity-blue?style=for-the-badge&logo=shield&logoColor=white" alt="Domain">
  <img src="https://img.shields.io/badge/Tools-Defender%20%7C%20Adlumin%20%7C%20Entra%20ID%20%7C%20KQL-orange?style=for-the-badge&logo=microsoft&logoColor=white" alt="Tools">
</p>

<p align="center">
  <b>Bridging frontline IT help desk operations with Cybersecurity Incident Response.</b><br>
  A curated collection of sanitized incident workflows, KQL hunting queries, and operational playbooks from a real-world educational IT environment.
</p>

---

## About This Repository

Hiring managers look for technical problem-solvers who can investigate telemetry, handle automated containment, and communicate calmly with users. This repository highlights how daily help-desk support scales into structured incident response across endpoint and cloud environments.

> **The Human Element:** Leveraging strong interpersonal communication—honed through coaching and high school IT support—to guide users smoothly through security incidents, credential resets, and device deployments.

---

## Core Investigation Workflows

<table>
  <tr>
    <td width="33%" valign="top">
      <h3>1. Endpoint Threat Triage</h3>
      <p><b>Platform:</b> Microsoft Defender for Endpoint</p>
      <p><b>Focus:</b> Investigating behavioral alerts, script executions, and unverified application installers.</p>
      <ul>
        <li><b>Telemetry:</b> Advanced Hunting (`DeviceProcessEvents`, `DeviceFileEvents`).</li>
        <li><b>Containment:</b> Manual isolation & IT leadership coordination for base reimaging.</li>
      </ul>
    </td>
    <td width="33%" valign="top">
      <h3>2. Cloud Identity & SOAR</h3>
      <p><b>Platform:</b> Adlumin / Entra ID / Windows SOAR</p>
      <p><b>Focus:</b> Triage of password spray patterns (MITRE <code>T1110.003</code> / <code>T1110.001</code>).</p>
      <ul>
        <li><b>Automation:</b> Tracking automated <code>domain_account/disable</code> playbooks across domain controllers.</li>
        <li><b>Analysis:</b> Reviewing error codes (<code>50140</code>, <code>399218</code>) and scoping unique user counts.</li>
      </ul>
    </td>
    <td width="33%" valign="top">
      <h3>3. False Positive Validation</h3>
      <p><b>Platform:</b> MDE & KQL Hunting</p>
      <p><b>Focus:</b> Differentiating true credential theft from legitimate browser profile migrations.</p>
      <ul>
        <li><b>Verification:</b> Inspecting command-line utility flags like `--utility-sub-type=chrome.mojom.ProfileImport`.</li>
        <li><b>Efficiency:</b> Fast resolution without user disruption.</li>
      </ul>
    </td>
  </tr>
</table>

---

## Sample KQL Hunting Queries (Sanitized)

### Check Process Execution & Command-Line Arguments
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "<device-name>"
| where FileName in~ ("installer.exe", "updater.exe") or ProcessCommandLine has "ProfileImport"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, ProcessCommandLine, AccountName
| sort by Timestamp desc
