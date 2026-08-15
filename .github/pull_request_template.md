## Summary

Describe the problem and the outcome of this change.

## Safety and security impact

Explain any effect on active assessment, network exposure, authentication, credentials, or hardware safety. Do not include real secrets or private network data.

## Validation

- [ ] Host tests pass: `python -m unittest discover -s tests -p "test_*.py" -v`
- [ ] The affected PlatformIO environment builds from a recursive checkout
- [ ] Generated credentials and TLS material remain untracked
- [ ] Public documentation and user-facing messages are in English

Hardware tested:

- [ ] LILYGO T-POE Pro
- [ ] Waveshare ESP32-S3-ETH
- [ ] Waveshare ESP32-P4-ETH
- [ ] Not tested on physical hardware

## Known limitations

List any remaining limitations or follow-up work.
