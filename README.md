# Windows Attack Detection Lab

A hands-on Windows detection engineering lab using Sysmon and Splunk Enterprise.

This project demonstrates the process of collecting endpoint telemetry, identifying excessive logging noise, tuning Sysmon collection, generating benign attack-like activity, and investigating the resulting events in Splunk.

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

**Windows activity → Sysmon → Windows Event Log → Splunk**

The Sysmon Operational event log was configured as a local Splunk input, allowing endpoint activity to be searched and investigated directly in Splunk.

![Sysmon telemetry successfully arriving in Splunk](images/01-sysmon-pipeline.png)

---

## Telemetry Tuning

The initial Sysmon configuration generated a large volume of telemetry. In a 15-minute window, the largest contributors included:

- Event ID 3: Network connections
- Event ID 5: Process termination
- Event ID 10: Process access

![Pre-tuning Sysmon event volume](images/02a-pre-tuning-noise.png)

The configuration was tuned to reduce high-volume noise while retaining telemetry useful for the lab.

![Updated Sysmon configuration](images/02b-config-update.png)

After tuning, the high-volume Event ID 5 and Event ID 10 activity was removed from the collected telemetry.

![Post-tuning Sysmon event distribution](images/02c-post-tuning-results.png)

---

## Detection 1: PowerShell File Creation

A benign PowerShell command downloaded a test file into the user's Downloads directory.

The resulting Sysmon activity included:

- Event ID 22: DNS query
- Event ID 3: Network connection
- Event ID 11: File creation

The shared `ProcessGuid` was used to correlate activity from the same PowerShell process.

![ProcessGuid pivot across related Sysmon events](images/03-processguid-pivot.png)

The raw Event ID 11 record showed `powershell.exe` creating the test file in the Downloads directory.

![Raw Sysmon Event ID 11 file creation event](images/04-raw-file-creation-event.png)

The raw XML was then converted into an analyst-friendly detection result containing the user, process image, target filename, and ProcessGuid.

![PowerShell file creation detection](images/05-powershell-file-detection.png)

Detection query:

[`detections/powershell-download.spl`](detections/powershell-download.spl)

---

## Detection 2: Run-Key Persistence

A benign persistence mechanism was created by adding a registry value to:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

The value `LabPersistence` was configured to launch:

`C:\Windows\System32\notepad.exe`

Sysmon Event ID 13 captured the registry modification.

The important fields were:

- `Image`: the process that performed the modification
- `TargetObject`: the Run-key registry value
- `Details`: the program configured to execute at logon
- `ProcessGuid`: the identifier used to pivot into related process activity

![Sysmon Event ID 13 Run-key persistence](images/06-run-key-persistence.png)

A ProcessGuid pivot was used to review related PowerShell activity and distinguish normal startup behavior from the actual persistence action.

Detection query:

[`detections/run-key-persistence.spl`](detections/run-key-persistence.spl)

---

## Project Files

- [`sysmonconfig.xml`](sysmonconfig.xml) — tuned Sysmon configuration used in the lab
- [`powershell-download.spl`](detections/powershell-download.spl) — PowerShell file creation detection
- [`run-key-persistence.spl`](detections/run-key-persistence.spl) — Run-key persistence detection

## Key Takeaways

- High-volume telemetry is not automatically useful telemetry.
- Sysmon collection should be tuned based on observed event volume.
- `ProcessGuid` provides a reliable way to correlate activity from the same process instance.
- Raw telemetry can be transformed into cleaner, analyst-friendly detection results.
- Parent processes, hashes, registry targets, and surrounding activity provide important investigative context.
- A legitimate binary such as PowerShell can still perform security-relevant actions, so behavior and context matter more than the executable name alone.
