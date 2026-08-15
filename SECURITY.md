# Security policy

## Experimental status

ESP32 OT Security Assessment is research software under active development. It has not received a complete independent security audit and must not be treated as a production security boundary.

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub's private vulnerability reporting form](https://github.com/il-prof-f-a/ESP32-OT-Security-Assessment/security/advisories/new). Do not publish exploit details in a regular issue before a fix is available.

Include the affected commit or version, target board, build environment, impact, and the smallest reproducible example you can provide. Redact all passwords, API keys, private keys, certificates containing private information, internal addresses, device identifiers, and proprietary OT traffic.

If a credential may have been exposed, rotate it immediately. Deleting the local generated credential set and rebuilding will create a new set, but deployed devices must then be updated accordingly.

## Authorized testing only

Security reports are welcome when research is performed against equipment and networks you own or are explicitly authorized to test. Do not disrupt third-party systems or production OT environments.
