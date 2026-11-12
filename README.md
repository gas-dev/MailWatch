# MailWatch

MailWatch is a self-hosted, read-only IMAP monitoring and notification service for regular email and certified mail accounts.

Created by [Techitapp](https://techitapp.com).

## Features

- Multiple IMAP accounts with TLS and encrypted saved credentials
- Read-only IMAP access (`EXAMINE` and `BODY.PEEK`): never marks messages as read, moves or deletes them
- Sender blacklist, message metadata, display names and short previews
- Configurable daily report time and new-mail alert times in Europe/Rome
- Delivery to individually managed SMTP recipients using SSL/TLS or STARTTLS
- An HTML report with mailbox counts, sender names, timestamps and summaries
- Manual report of the last 60 days of monitored INBOX messages
- SQLite persistence for tracking already notified messages and avoiding repeats
- Administrator login, password hashing, CSRF validation and security headers
- Techitapp dashboard with connection diagnostics and recent operations

## Requirements

- Debian-based Linux host with Python 3 and systemd
- An IMAP account with an application-specific password or another supported login method
- An authenticated SMTP provider
- HTTPS and a separate access-control layer if exposed outside a trusted LAN

## Installation

```bash
git clone https://github.com/gas-dev/MailWatch.git
cd MailWatch
sudo bash install.sh
```

The installer prompts for an administrator password and creates a dedicated, unprivileged service user. It stores local runtime data in `/var/lib/mailwatch` and service environment secrets in `/etc/mailwatch/service.env`, outside the Git repository.

By default the application binds to `127.0.0.1:8092`. To access it remotely, use an SSH tunnel or a carefully secured HTTPS reverse proxy. For a LAN bind, configure `MAILWATCH_BIND` in the private service environment.

## Security checklist for Internet deployments

1. Put the application behind HTTPS. Prefer Cloudflare Access, a VPN, or another independent identity layer with MFA.
2. Set `MAILWATCH_HTTPS=1` in `/etc/mailwatch/service.env` when using HTTPS so session cookies have the Secure attribute. Plain HTTP access may then fail to maintain a login.
3. Do not expose port 8092 directly to the public Internet. Restrict host firewall rules accordingly.
4. Use separate, revocable IMAP and SMTP application passwords with the minimum provider permissions. Rotate credentials if accidentally disclosed.
5. Keep the operating system and Python dependencies updated. The supplied GitHub Actions workflow checks Python syntax only, not full security.
6. Back up the private SQLite database and encryption key together, with access restricted to the service administrator.
7. Never commit `service.env`, `secret.key`, databases, authentication cookies, access tokens, logs, or production mail previews.
8. Confirm all hosted domains and reverse-proxy protections before sharing the public service URL.

## Behavior

The first scan records a per-mailbox IMAP UID baseline. Emails already present at that point are treated as historical and are not sent as automatic new-mail alerts. Subsequent polling sends pending messages only once, after a successful submission to SMTP.

Scheduled digests and alerts do not send empty emails. The daily digest sends pending newly detected messages, rather than repeating all of the previous day's messages.

Manual `Request last 60 days` scans all configured INBOX folders for messages with an IMAP internal date within the last 60 days. It excludes blacklisted senders, includes a mailbox-by-mailbox count and readable previews, and splits large reports into parts. Successfully sent messages are marked as notified in local SQLite.

No IMAP messages, read flags, folders, attachments or content are modified.

## Operations

```bash
sudo systemctl status mailwatch
sudo journalctl -u mailwatch --no-pager -n 40
```

For updates, pull the code, compile the Python files, copy the application files into `/opt/mailwatch/`, then restart the service.

## Notes

- IMAP monitoring currently covers INBOX, not Sent, Archive or other folders.
- SMTP delivery acceptance is not proof of final mailbox delivery. Check recipient delivery when needed.
- A server crash or mail-provider timeout may create an ambiguous delivery outcome. Check the logs before manually repeating a report.
- Application security depends on your reverse proxy, TLS, host configuration, credentials and updates.
