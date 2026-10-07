"""Attack and benign sample events for each Sigma rule.

Keyed by rule filename stem. ``attack`` events must fire the rule; ``benign``
events must stay silent. All data is from a generic lab (CORP.LOCAL), not from
any real or exam environment.
"""

VECTORS: dict[str, dict[str, list[dict]]] = {
    "kerberoasting": {
        "attack": [
            # RC4 service ticket requested for a user-created service account.
            {
                "EventID": 4769,
                "TicketEncryptionType": "0x17",
                "ServiceName": "svc_sql",
                "TargetUserName": "jdoe@CORP.LOCAL",
            },
        ],
        "benign": [
            # AES ticket for the same service account.
            {"EventID": 4769, "TicketEncryptionType": "0x12", "ServiceName": "svc_sql"},
            # RC4 but for a machine account (ends in $).
            {"EventID": 4769, "TicketEncryptionType": "0x17", "ServiceName": "WS01$"},
            # RC4 for krbtgt (explicitly excluded).
            {"EventID": 4769, "TicketEncryptionType": "0x17", "ServiceName": "krbtgt"},
        ],
    },
    "dcsync_ntds": {
        "attack": [
            # A user account exercises directory replication rights.
            {
                "EventID": 4662,
                "SubjectUserName": "jdoe",
                "Properties": "Replicating Directory Changes "
                "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
            },
        ],
        "benign": [
            # Legitimate replication by a domain controller machine account.
            {
                "EventID": 4662,
                "SubjectUserName": "DC01$",
                "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
            },
            # A 4662 that is not a replication operation.
            {
                "EventID": 4662,
                "SubjectUserName": "jdoe",
                "Properties": "{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
            },
        ],
    },
    "lsass_credential_access": {
        "attack": [
            # Mimikatz-style handle to LSASS with a memory-read access mask.
            {
                "EventID": 10,
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x1410",
                "SourceImage": r"C:\Users\jdoe\Downloads\mk.exe",
            },
            # Same mask in the zero-padded form real EVTX logs carry
            # (caught by replaying EVTX-ATTACK-SAMPLES, not by this vector).
            {
                "EventID": 10,
                "TargetImage": r"C:\Windows\system32\lsass.exe",
                "GrantedAccess": "0x00001010",
                "SourceImage": r"C:\Users\IEUser\Desktop\mimikatz.exe",
            },
        ],
        "benign": [
            # Benign low-privilege handle to LSASS (zero-padded form too).
            {
                "EventID": 10,
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x1000",
                "SourceImage": r"C:\Windows\System32\svchost.exe",
            },
            {
                "EventID": 10,
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x00001000",
                "SourceImage": r"C:\Windows\System32\svchost.exe",
            },
            # Antimalware service reading LSASS (filtered out).
            {
                "EventID": 10,
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x1410",
                "SourceImage": r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe",
            },
        ],
    },
    "pass_the_hash": {
        "attack": [
            # NewCredentials logon injected via seclogo / Negotiate (sekurlsa::pth).
            {
                "EventID": 4624,
                "LogonType": 9,
                "LogonProcessName": "seclogo",
                "AuthenticationPackageName": "Negotiate",
                "TargetUserName": "administrator",
            },
        ],
        "benign": [
            # Ordinary interactive logon.
            {
                "EventID": 4624,
                "LogonType": 2,
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
            },
            # NewCredentials logon that used Kerberos, not injected hashes.
            {
                "EventID": 4624,
                "LogonType": 9,
                "LogonProcessName": "Kerberos",
                "AuthenticationPackageName": "Kerberos",
            },
        ],
    },
    "llmnr_nbtns_poisoning": {
        "attack": [
            # Host emits an LLMNR response (source port 5355) — responder behaviour.
            {
                "EventID": 3,
                "Protocol": "udp",
                "Initiated": True,
                "SourcePort": 5355,
                "DestinationPort": 50124,
                "SourceIp": "10.10.0.5",
            },
        ],
        "benign": [
            # Normal client LLMNR query (destination port 5355).
            {
                "EventID": 3,
                "Protocol": "udp",
                "Initiated": True,
                "SourcePort": 50124,
                "DestinationPort": 5355,
            },
            # Unrelated TCP connection.
            {"EventID": 3, "Protocol": "tcp", "Initiated": True, "SourcePort": 445},
        ],
    },
}
