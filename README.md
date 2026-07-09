# Windows Attack Detection Lab

A hands-on Windows detection engineering lab using Sysmon and Splunk Enterprise.

The project demonstrates the process of collecting endpoint telemetry, identifying excessive logging noise, tuning Sysmon collection, generating benign attack-like activity, and investigating the resulting events in Splunk.

## Lab Environment

- Windows virtual machine
- Sysmon 15.21
- Splunk Enterprise
- PowerShell

## Project Objectives

- Configure Sysmon endpoint telemetry
- Ingest the Sysmon Operational event log into Splunk
- Measure and reduce noisy telemetry
- Detect PowerShell file creation activity
- Correlate related events using ProcessGuid
- Detect Windows Run-key persistence

## Telemetry Pipeline

Windows activity → Sysmon → Windows Event Log → Splunk

## Detection 1: PowerShell File Creation

A benign PowerShell command downloaded a test file into the user's Downloads directory.

The resulting Sysmon activity included:

- Event ID 22: DNS query
- Event ID 3: Network connection
- Event ID 11: File creation

The shared ProcessGuid was used to correlate activity from the same PowerShell process.

## Detection 2: Run-Key Persistence

A benign persistence mechanism was created by adding a registry value to:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

The value `LabPersistence` was configured to launch `notepad.exe` at user logon.

Sysmon Event ID 13 captured the registry modification. A ProcessGuid pivot was then used to distinguish the persistence action from normal PowerShell startup activity.

## Key Takeaways

- High-volume telemetry is not automatically useful telemetry.
- Sysmon configuration should be tuned based on observed event volume.
- ProcessGuid provides a reliable way to correlate activity from the same process instance.
- Parent processes, hashes, registry targets, and surrounding activity all provide important investigative context.
