# MailLens Telegram Bot

MailLens is a Telegram-based email and domain inspection tool that checks email address syntax, retrieves DNS MX records, and performs SMTP diagnostics to assess mail server responses and security restrictions.

## Features

- `/check user@example.com` — Checks a single email address.
- `/mx example.com` — Retrieves the domain's MX records.
- `/checklist` — Prompts for a TXT file and generates a CSV report.
- Supports TXT files containing email addresses separated by newlines, commas, semicolons, spaces, or tabs.
- Automatically removes duplicate email addresses.
- Performs SMTP checks sequentially with configurable delays.
- Classifies SMTP outcomes, including:
  - Mailbox-not-found signals.
  - Accepted-but-unconfirmed responses.
  - Temporary failures.
  - Connection failures.
  - Server security and policy restrictions.
  - Sender IP or domain reputation restrictions.

## Setup

### Requirements

- Node.js 20 or newer.
- A Telegram bot token from [BotFather](https://t.me/BotFather).

### Installation

1. Clone the repository.
2. Install dependencies:

   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env`.
4. Configure the environment variables.
5. Start the bot:

   ```bash
   npm start
   ```

## Environment Variables

| Variable | Description |
|---|---|
| `BOT_TOKEN` | Telegram bot token obtained from BotFather. |
| `SENDER_EMAIL` | Sender address used in the SMTP envelope. |
| `HELO_HOSTNAME` | Hostname supplied during the SMTP EHLO handshake. |
| `SMTP_TIMEOUT` | SMTP connection timeout in milliseconds. |
| `SMTP_DELAY_MS` | Delay between addresses in bulk checks. |
| `MAX_FILE_BYTES` | Maximum permitted TXT upload size. |
| `MAX_EMAILS` | Maximum number of unique email addresses per TXT file. |

## SMTP Diagnostics and Limitations

MailLens performs SMTP recipient-stage diagnostics for domains with discoverable MX records.

It establishes an SMTP connection, performs the EHLO handshake, submits the configured sender address using `MAIL FROM`, and checks recipient acceptance using `RCPT TO`.

MailLens does not send message content using the SMTP `DATA` command. It does not use proxies or attempt to bypass email provider security controls.

Only test email addresses and domains you own or are explicitly authorised to assess.

Many email providers intentionally suppress recipient-existence information, accept all recipients, defer verification, or reject recipient checks based on sender IP reputation and security policies.

Consequently:

- `accepted_unconfirmed` does not prove that a mailbox exists.
- `mailbox_not_found_signal` indicates an explicit server response suggesting that the mailbox does not exist, but is not absolute proof.
- `server_security_or_policy_restriction` indicates that the server declined the verification attempt under a security or policy rule.
- `sender_ip_or_domain_blocklisted` indicates that the response appears to identify a sender reputation or blocklist issue.
- `connection_blocked` may occur when the hosting provider blocks outbound TCP port 25.

DNS MX lookup and SMTP diagnostics are separate operations. MX lookup can succeed even when SMTP connectivity is unavailable.

## Deployment

MailLens can be deployed as a separate Docker application or worker in Coolify.

A public domain or exposed inbound application port is not required because the bot uses Telegram long polling.

The deployment environment must permit:

- Outbound HTTPS connections to the Telegram Bot API.
- Outbound SMTP connections over TCP port 25 for SMTP diagnostics.

If outbound port 25 is blocked, MailLens can continue performing email syntax and MX record checks, but SMTP diagnostics will report connection failures.

## License

Private project. All rights reserved.