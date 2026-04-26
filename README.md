# Wazuh SIEM Home Lab

A hands-on Security Information and Event Management (SIEM) lab built using Wazuh, designed to simulate real-world SOC analyst workflows including threat detection, alert investigation, custom rule authoring, and MITRE ATT&CK mapping.

---

## Lab Environment

| VM | OS | IP | Role |
|---|---|---|---|
| Kali Linux | Kali Rolling | 10.0.2.5 | Wazuh Manager (SIEM Backend + Dashboard) |
| Windows Server 2019 | Windows Server 2019 | 10.0.2.15 | Wazuh Agent — Monitoring Target |
| Windows 11 Pro | Windows 11 Pro | 10.0.2.122 | Wazuh Agent — Endpoint + Attack Simulation |

**Network:** VirtualBox NAT Network (LabNetwork) — 10.0.2.0/24

---

## Objectives

- Deploy a fully functional SIEM using Wazuh on a home lab network
- Monitor Windows endpoints with rich telemetry via Sysmon
- Write and validate custom detection rules mapped to MITRE ATT&CK
- Configure File Integrity Monitoring (FIM) to detect unauthorized file changes
- Simulate attack scenarios and investigate alerts as a SOC analyst
- Practice the full detection-to-escalation workflow

---

## Tools & Technologies

- **Wazuh 4.7.5** — SIEM platform (Manager, Indexer, Dashboard)
- **Sysmon v15.20** with SwiftOnSecurity config — endpoint telemetry
- **VirtualBox** — hypervisor
- **Windows Event Logging** — native Windows security logs
- **MITRE ATT&CK Framework** — threat intelligence mapping

---

## Phase 1 — Wazuh Manager Deployment (Kali Linux)

Deployed the Wazuh all-in-one stack on Kali Linux using the official install script. This sets up three components on a single host:

- **Wazuh Indexer** — stores and indexes all security events
- **Wazuh Manager** — receives agent telemetry, runs detection rules, generates alerts
- **Wazuh Dashboard** — web-based UI accessible at https://10.0.2.5

Configured a static IP on Kali (10.0.2.5) and verified full connectivity to both Windows VMs before installation.

---

## Phase 2 — Agent Deployment & Sysmon

Installed the Wazuh agent on both Windows endpoints, pointing each to the Kali Manager at 10.0.2.5. Both agents registered and came up Active within minutes.

Installed **Sysmon** with the SwiftOnSecurity baseline configuration on both Windows VMs. Sysmon captures:

- **Event ID 1** — Process creation
- **Event ID 3** — Network connections
- **Event ID 11** — File creation
- **Event ID 13** — Registry changes

Added the Sysmon event channel to each agent's `ossec.conf` to ensure Wazuh collects Sysmon logs in addition to standard Windows Security events.

**Result:** Both agents reporting Active with 100% coverage. Security events began flowing immediately after Sysmon configuration.

---

## Phase 3 — Custom Detection Rule

Authored a custom detection rule in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager to detect PowerShell encoded command execution — a common attacker evasion technique.

**Rule logic:**
- Monitors the `win.eventdata.commandLine` field on all Windows events
- Uses PCRE2 regex to match `-EncodedCommand`, `-enc`, or base64-like strings
- Fires at **Level 12** (high severity)
- Tagged to **MITRE ATT&CK T1059.001** — Command and Scripting Interpreter: PowerShell

Verified the rule via the Wazuh Management > Rules portal and confirmed it appears alongside built-in rules with proper MITRE compliance tagging.

---

## Phase 4 — File Integrity Monitoring (FIM)

Configured FIM on the Windows 11 endpoint by editing `ossec.conf` to monitor `C:\Temp` in realtime. When a file was created in that directory via File Explorer:

- Wazuh **Rule 92213** fired automatically at **Level 15** (critical)
- Mapped to **MITRE T1105 — Ingress Tool Transfer**
- Tagged under **Command and Control** tactic
- Sysmon Event ID 11 captured the file creation and fed it to the Wazuh detection engine

This demonstrated that `C:\Temp` is recognized by Wazuh's built-in Sysmon ruleset as a directory commonly used by malware to stage files — no manual simulation required.

---

## Phase 5 — Brute Force Detection & Incident Escalation

Simulated a brute force attack by attempting 6 failed RDP logins against Windows Server from Windows 11. Wazuh detected the pattern immediately:

- **5 consecutive** "Logon failure - Unknown user or bad password" alerts within 16 seconds
- **Rule 60122** — watches Windows Event ID 4625 (failed logon)
- **MITRE T1110 — Brute Force** under Credential Access tactic
- Compliance mapped to **GDPR, HIPAA, GPG 13**
- Followed by a **successful logon** — indicating potential account compromise

### SOC Analyst Escalation Summary

| Field | Detail |
|---|---|
| **Incident Type** | Brute Force / Credential Access |
| **Source** | Windows 11 (10.0.2.122) |
| **Target** | Windows Server (10.0.2.15) |
| **Timeframe** | 15:34:07 — 15:34:23 (16 seconds) |
| **Failed Attempts** | 5 |
| **Outcome** | Successful logon at 15:35:05 |
| **MITRE Technique** | T1110 — Brute Force |
| **Severity** | Medium (Level 5 per attempt) — escalated due to pattern + success |
| **Recommended Action** | Escalate to Tier 2, lock account, investigate successful session |

---

## MITRE ATT&CK Coverage

The lab organically generated detections across 9 MITRE ATT&CK tactics:

| Tactic | Alert Count |
|---|---|
| Discovery | 56 |
| Defense Evasion | 24 |
| Persistence | 23 |
| Privilege Escalation | 23 |
| Initial Access | 20 |
| Lateral Movement | 8 |
| Command and Control | 8 |
| Execution | 5 |
| Impact | 1 |

**Key techniques detected:**
- T1078 — Valid Accounts (20 hits)
- T1570 — Lateral Tool Transfer (8 hits)
- T1105 — Ingress Tool Transfer (8 hits)
- T1059.001 — PowerShell (3 hits — custom rule)
- T1562.001 — Disable or Modify Tools (3 hits)
- T1059.003 — Windows Command Shell (2 hits)
- T1543.003 — Windows Service (2 hits)

---

## Key Takeaways

- Deploying a SIEM from scratch requires careful attention to network configuration, agent-manager connectivity, and log source configuration
- Sysmon dramatically enriches Windows telemetry and enables technique-level MITRE mapping that standard Windows logs alone cannot provide
- Writing custom detection rules requires understanding the event field structure — knowing which field to inspect (e.g. `win.eventdata.commandLine`) is as important as the rule logic itself
- FIM is a high-value, low-overhead detection capability — monitoring sensitive directories catches both malware staging and insider threat activity
- A brute force alert alone is medium severity, but when followed by a successful logon it becomes a potential account compromise requiring immediate Tier 2 escalation

---

## Related Projects

- [Nessus Vulnerability Management Lab](https://github.com/gaurav-koshti-CySA/Nessus_Vuln_Management_Lab)
- [Entra IAM Lab](https://github.com/gaurav-koshti-CySA/Entra_Iam_Lab)

---

*Gaurav Koshti | CompTIA Security+ | Pursuing CySA+ | LinkedIn: linkedin.com/in/gaurav-koshti*
