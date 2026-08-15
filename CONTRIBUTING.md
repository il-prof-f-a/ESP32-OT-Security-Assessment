# Contributing

Thank you for helping improve ESP32 OT Security Assessment. The project is experimental and changes should preserve safe, reproducible laboratory use across the supported targets.

## Before opening a pull request

1. Discuss substantial behavior or architecture changes in a GitHub issue first.
2. Never commit credentials, generated certificates, private network captures, customer data, or proprietary device information.
3. Add or update host-side tests for code and build-integration changes.
4. Run `python -m unittest discover -s tests -p "test_*.py" -v`.
5. Build the affected PlatformIO environment and state which physical hardware, if any, you tested.
6. Keep public documentation, diagrams, issue text, and user-facing build messages in English.

## Pull request notes

Describe the problem, the chosen approach, safety implications, tests performed, target-board impact, and known limitations. Hardware validation claims must identify the exact board and network arrangement used.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md), not a public issue or pull request.

## License

Unless explicitly agreed otherwise, contributions are provided under the repository's [PolyForm Noncommercial License 1.0.0](LICENSE.md) and must preserve its required notice.
