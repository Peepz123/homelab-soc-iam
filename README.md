# homelab-soc-iam
Self-built cybersecurity home lab — network segmentation, SIEM, Active Directory, detection engineering
## Phase 3 — SIEM / Detection (Wazuh)

**Stack:** Wazuh 4.14 (all-in-one: manager + indexer + dashboard) on Ubuntu Server, agent-based Windows log collection.

### Objective
Deploy a SIEM/XDR capable of ingesting security telemetry from the `lab.local`
domain, applying detection rules, and surfacing alerts — providing the
visibility needed to detect the adversary simulation in Phase 4.

### Architecture
```
pfSense (192.168.10.1) ─── labnet
   │
   ├── DC01 (192.168.10.10) ── Wazuh agent → forwards Windows Security event log
   │
   └── Wazuh Server (192.168.10.20) ── manager + indexer + dashboard (web UI)
```

| Component | Detail |
|-----------|--------|
| Wazuh server | Ubuntu Server, static `192.168.10.20`, 4GB/2 cores |
| Install method | Assisted all-in-one (`wazuh-install.sh -a`) |
| Dashboard | `https://192.168.10.20` (self-signed TLS) |
| Monitored endpoint | DC01 (Windows Server 2022) via Wazuh agent |
| Log source | Windows Security channel (logon, Kerberos, account mgmt) |

### Design decision — Wazuh over Security Onion
Security Onion's practical baseline (~12–16GB RAM, 200GB disk) exceeds what a
16GB laptop host can allocate while keeping pfSense and the Domain Controller
running concurrently. Wazuh delivers equivalent SIEM/XDR capability —
log ingestion, detection rules, MITRE ATT&CK mapping, dashboards, alerting —
within a ~4GB footprint, allowing the SIEM, target, and attacker to run
**simultaneously** on the same host. This is a prerequisite for live
attack→detect exercises in Phase 4.

Selecting the tool that fits the resource envelope while preserving the
required capability is a deliberate engineering trade-off, not a compromise:
Wazuh is widely used in industry and carries equal weight for SOC and
security-engineering work.

### Agent-based Windows log collection
Rather than forwarding logs over the network with a syslog collector, the
Wazuh **agent** is installed directly on DC01. The agent reads the Windows
Security event log locally and ships it to the manager over an authenticated,
encrypted channel (ports 1514/1515). This approach:
- captures native Windows event IDs (4624/4625 logon, 4769 Kerberos service
  ticket, 4720+ account management) with full fidelity;
- requires no changes to the Windows audit *transport*, only the audit
  *policy* already set in Phase 2;
- scales cleanly — additional endpoints are onboarded by deploying the agent.

The audit policy configured during Phase 2 hardening is what makes these
events available for collection, tying the two phases together: **you can only
detect what you first chose to log.**

### Verification
- Wazuh manager, indexer, and dashboard services confirmed `active (running)`.
- DC01 registered and reported **Active** in the Agents view.
- Windows logon events (4624) confirmed flowing into Security Events after a
  test logon on DC01.

### Outcome
A functioning SIEM ingesting security telemetry from a hardened Active
Directory environment — the detection foundation for the Phase 4
Kerberoasting attack→detect exercise (event **4769**).