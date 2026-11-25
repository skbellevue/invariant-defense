"""MITRE ATT&CK technique names used in alerts (subset, for readable reports)."""

TECHNIQUES = {
    "T1027.014": "Obfuscated Files or Information: Polymorphic Code",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1074.001": "Data Staged: Local Data Staging",
    "T1078": "Valid Accounts",
    "T1078.001": "Valid Accounts: Default Accounts",
    "T1082": "System Information Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1033": "System Owner/User Discovery",
    "T1057": "Process Discovery",
    "T1087": "Account Discovery",
    "T1091": "Replication Through Removable Media",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1136": "Create Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1190": "Exploit Public-Facing Application",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1496": "Resource Hijacking",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1550": "Use Alternate Authentication Material",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1567": "Exfiltration Over Web Service",
    "T1573": "Encrypted Channel",
    "T1606": "Forge Web Credentials",
    "T1606.001": "Forge Web Credentials: Web Cookies",
    "T1053": "Scheduled Task/Job",
    "T1562": "Impair Defenses",
    "T1204": "User Execution",
}


def name(technique: str) -> str:
    return TECHNIQUES.get(technique, technique)
