# share-safe

Make logs, stack traces, config files and error messages safe to share: API keys, tokens,
passwords, emails, IPs and more become consistent placeholders. Pure Python, no dependencies.

**Status: early development.** Built in small steps; checked items exist and are tested.

- [x] Detectors for secrets, personal data and infrastructure
- [ ] Consistent placeholders, restore, random-string safety net
- [ ] Command line: redact, check, restore, kinds
- [ ] Claude skill (SKILL.md) and a sample log
- [ ] Full documentation and demo

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
