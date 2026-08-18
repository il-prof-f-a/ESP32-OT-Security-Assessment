# Contributing

Thank you for helping improve ESP32 OT Security Assessment. The firmware is experimental, and
changes must preserve safe, reproducible laboratory use on all supported targets.

## Before opening a pull request

1. Discuss substantial behavior or architecture changes in a GitHub issue first.
2. Never commit passwords, setup tokens, private keys, private captures, customer information,
   internal addresses or proprietary device data.
3. Add or update host tests for firmware, tooling and build-integration changes.
4. Run:

   ```bash
   python -m unittest discover -s tests -p "test_*.py" -v
   python scripts/check_release_secrets.py --repository .
   ```

5. Firmware or build changes must compile all three environments:

   ```bash
   pio run -e t-poe-pro
   pio run -e esp32-s3-eth
   pio run -e waveshare-esp32p4-eth
   ```

6. Keep public documentation, diagrams, issue text and user-facing build messages in English.

Describe the problem, approach, security implications, tests, board impact and known limitations
in the pull request. Hardware validation claims must identify the board and network arrangement.
Report security-sensitive findings through the private process in [SECURITY.md](SECURITY.md).

## License

Contributions are provided under the repository's
[PolyForm Noncommercial License 1.0.0](LICENSE.md) unless the owner agrees otherwise. This project
is source-available and is not OSI-approved open-source software. Contributions must preserve the
required copyright notice.
