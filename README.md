# MailLens Telegram Bot

MailLens inspects email syntax, DNS MX records, and SMTP server responses.

## Features

- `/check user@example.com` checks one address.
- `/mx example.com` retrieves MX records.
- `/checklist` prompts for a TXT file and produces a CSV report.
- TXT files accept newlines, commas, semicolons, spaces, and tabs.
- Duplicate email addresses are removed.
- SMTP checks are sequential and rate-limited.
- SMTP outcomes distinguish mailbox-not-found signals, accepted-but-unconfirmed responses, temporary failures, connection failures, and server security/policy restrictions.

## Setup

1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Copy `.env.example` to `.env`.
4. Set `BOT_TOKEN` and `SENDER_EMAIL`.
5. Run `npm start`.

## Environment variables

- `BOT_TOKEN`: Telegram bot token from BotFather.
- `SENDER_EMAIL`: sender address used in the SMTP envelope.
- `HELO_HOSTNAME`: hostname sent with EHLO.
- `SMTP_TIMEOUT`: socket timeout in milliseconds.
- `SMTP_DELAY_MS`: delay between addresses in a bulk job.
- `MAX_FILE_BYTES`: maximum TXT upload size.
- `MAX_EMAILS`: maximum unique addresses per TXT file.

## Important SMTP limitations

MailLens attempts SMTP recipient-stage diagnostics for domains with MX records. It does not send message content (`DATA`), and it does not use proxies or attempt to bypass provider protections.

Only test addresses and domains you own or are explicitly authorised to assess. Many providers intentionally suppress recipient-existence information, accept all recipients, defer checks, or reject verification based on sender IP reputation or policy. Therefore:

- `accepted_unconfirmed` does not prove that a mailbox exists.
- `mailbox_not_found_signal` is a server response signal, not absolute proof.
- `server_security_or_policy_restriction` means the server declined the verification attempt under a security or policy rule.
- `sender_ip_or_domain_blocklisted` means the response appears to identify a reputation/blocklist issue.
- `connection_blocked` can also occur when the hosting provider blocks outbound TCP port 25.

## Deployment

Deploy as a separate Docker application or worker in Coolify. No inbound port or public domain is required for Telegram long polling. The host must permit outbound HTTPS to Telegram and outbound SMTP TCP port 25 for SMTP diagnostics. If outbound port 25 is blocked, MX lookup will still work, but SMTP checks will report connection errors.
