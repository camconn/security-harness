
# Security Harness
This is a repo which has a simple security auditing harness.

# Setup
You must have Python and `uv` installed. `uv sync`

## API Keys

Set the appropriate environment variable for your chosen provider before running:

- **Anthropic:** `ANTHROPIC_API_KEY`
- **OpenAI:** `OPENAI_API_KEY`

```sh
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
```

These can also be placed in a `.env` file in the project root.
Running with `uv run --env-file .env` will load these automatically.

# Run
For information, run `main.py` with `--help`

`uv run security-harness`

# TODO
* Give agents an email.
    * Lots of vulnerabilities are related to email
    * Give agents a way to receive emails at an ephemeral address
