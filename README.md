# API Security Tests

Automated security tests for 3 staging API endpoints. The idea is to think like an ethical hacker and try to break things -- auth bypass, injections, OTP bypass, race conditions, etc.

I also integrated OpenAI (GPT-4) to help analyze API responses for vulnerabilities, which is what the `ai_analyzer.py` file does. It's completely optional -- only kicks in if you have an `OPENAI_API_KEY` set.

## APIs covered

| API | Endpoint | What I tested |
|-----|----------|---------------|
| Create Pickup | `POST /pickups` | auth bypass, SQLi, XSS, SSRF, business logic |
| Update Bank Info | `POST /businesses/add-bank-info` | JWT tampering, OTP bypass, race conditions |
| Forget Password | `POST /users/forget-password` | email enumeration, timing attacks, injection |

## Quick start

```
pip install -r requirements.txt
pytest
```

Some useful commands:
```
pytest tests/pickup/            # just pickup
pytest tests/bank_info/         # just bank info
pytest -m critical              # only critical stuff
pytest -m injection             # only injection tests
pytest --html=reports/out.html  # generate html report
```

## Project layout

- `framework/` -- HTTP client, JWT manipulation utils, AI analyzer (uses OpenAI to scan responses)
- `payloads/` -- all attack strings organized in one place (SQLi, XSS, NoSQL, SSRF, OTP bypass values)
- `tests/conftest.py` -- shared fixtures so I don't repeat the same setup everywhere
- `tests/<api>/` -- each API gets its own folder with auth, injection, and validation tests
- `.github/workflows/` -- CI/CD pipeline that runs on every push, PR, and nightly at 3 AM

## About the AI analyzer

The task asked to use OpenAI to help with security testing. So `framework/ai_analyzer.py` sends API responses to GPT-4 and asks it to look for info leakage, missing headers, bad error handling, etc. If you don't set the API key it just skips silently.

## Token stuff

The bank info endpoint uses a JWT that expires. The framework tries to auto-refresh it by calling:
```
POST /api/v2/users/generate-token-for-interview-task
```
If that doesn't work, set `BANK_INFO_AUTH_TOKEN` as an env var.

## CI/CD

GitHub Actions workflow at `.github/workflows/security-tests.yml`:
- Runs on push to main/develop, PRs, and nightly
- Tests each API in parallel (matrix strategy)
- Runs critical tests separately as a gate
- Uploads HTML + XML reports as artifacts
- Generates a summary with pass/fail counts
