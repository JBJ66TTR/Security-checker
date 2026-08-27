# Security Checker

Security Checker is a browser-based tool that checks source code for
patterns that may indicate accidentally exposed secrets.

## Features

- API key detection
- Password detection
- Access token detection
- Private key detection
- Database credential detection
- Line-number reporting
- Security remediation advice
- Client-side scanning

## Privacy

The MVP performs scanning directly in the browser.

Source code is not sent to a server by this version.

## Important

This tool detects suspicious patterns. A finding does not necessarily mean
that a value is a valid or active credential.

If a real credential has been exposed publicly, revoke or rotate it
immediately.

## Run locally

Open `index.html` in a browser.

## License

MIT
