# WARRIOR

WARRIOR is a read-only Linux exposure review script written as a single Bash file.

It is meant for local enumeration and reporting. The script does not modify the host, run exploits, or print copy-paste privilege escalation commands.

## What it does

WARRIOR reviews a Linux system and highlights findings that may deserve attention during a security assessment. It focuses on readable output and simple prioritization.

The script reports:

- confidence grading
- likely impact
- service-chain observations
- ACL and parent-directory issues
- secret-related findings
- correlated risk paths
- an overall machine risk score

## Usage

```bash
bash warrior.sh
bash warrior.sh --quick
bash warrior.sh --normal
bash warrior.sh --deep
bash warrior.sh --deep --no-color
```

## Scan modes

- `quick` keeps the run short and covers the basics
- `normal` adds service and secret checks
- `deep` adds ACL and parent-directory review

## Notes

All findings require manual validation.
