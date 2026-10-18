# Contributing to GBLOXKOS MORPHEUS

Thanks for your interest in improving GBLOXKOS MORPHEUS V.1.

## Before you open a pull request

Run both checks locally and make sure they are clean:

```bash
python3 audit.py
python3 -m pyflakes app.py threat_feed.py audit.py
```

The current release passes both with **0 errors and 0 warnings**. CI runs the same
checks, so anything failing locally will fail on the pull request.

## Guidelines

- **Keep changes focused.** One logical change per pull request.
- **Document new endpoints.** Update the API table in `README.md`.
- **Preserve security properties.** Client-supplied system prompts must stay
  rejected, and fetched third-party content must stay sanitised.
- **Never commit secrets.** Use the `API_TOKEN` environment variable.
- **Don't commit runtime state.** `data/`, logs, and PID files are git-ignored.
- **Match existing style.** The codebase follows PEP 8 with descriptive docstrings
  on public classes and methods.

## Reporting bugs

Please include:

1. Python version and OS
2. Whether Ollama is running, and which models are pulled
3. The relevant portion of `app.err`
4. Steps to reproduce

## Reporting security issues

Please report security vulnerabilities privately to the maintainers of
**GBLOXKOS LLC** rather than opening a public issue.

## License

Contributions are accepted under the MIT License. See [LICENSE](LICENSE).
