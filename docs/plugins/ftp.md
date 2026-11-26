# FTP

FTP client: browse, view, copy, move, rename and delete files on FTP servers like a local folder.
FTPS (explicit TLS) is the separate `ftps` plugin, which uses this plugin's library.

## How to use

- **Ctrl+F** (Net > FTP Connect): pick a bookmark, or type `ftp://[user@]host[:port]/path`.
  Without a user you log in anonymously.
- `ftp://` lists your bookmarks; `ftp://<bookmark>` opens one.
- F3 / F4 / F5 / F6 / F7 / F8 work as on disk; F4 uploads every save. Interrupted transfers can be
  resumed.

## Setup: bookmarks (`ftp.toml`)

Next to `config.toml`: `%APPDATA%\commander\ftp.toml` (Windows), `~/.config/commander/ftp.toml`
(Linux, macOS). Env `COMMANDER_FTP_CONFIG` points elsewhere.

```toml
[work]              # open with ftp://work
host = "ftp.example.com"
port = 21           # optional
user = "me"         # optional, none = anonymous
password = "secret" # optional
tls = true          # optional: explicit FTPS (AUTH TLS)
```

## Config keys

| Key | Meaning |
|---|---|
| `host` | Server name (required) |
| `port` | Default 21 |
| `user`, `password` | Login; none = anonymous |
| `tls` | `true` = explicit FTPS |

Passwords go only in `ftp.toml`: a `user:password@` URL is refused, so a password never lands in
history, tabs or config.

## Limitations

- Passive mode only.
- FTPS certificates must be valid (self-signed servers fail); no implicit FTPS (port 990).
