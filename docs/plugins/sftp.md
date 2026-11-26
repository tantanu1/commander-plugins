# SFTP

SFTP client (SSH file transfer): browse, view, copy, move, rename and delete files on SSH servers
like a local folder. Host keys are always checked.

## How to use

- **Ctrl+F** (the same dialog lists FTP and SFTP bookmarks) or type
  `sftp://[user@]host[:port]/path`. Without a user, your local user name is used.
- `sftp://` lists your bookmarks; `sftp://<bookmark>` opens one.
- `sftp://<alias>` also works for any `Host` alias in `~/.ssh/config` (HostName, User, Port,
  IdentityFile, IdentitiesOnly; ProxyCommand/Match/Include are ignored, nothing is executed).
- In Ctrl+F, **F7** adds and **F4** edits an SFTP bookmark (host, port, user, private key file,
  optional password saved only when "Save password" is ticked).
- F3 / F4 / F5 / F6 / F7 / F8 work as on disk; F4 uploads every save.

## Setup: bookmarks (`sftp.toml`)

Next to `config.toml` (env `COMMANDER_SFTP_CONFIG` points elsewhere):

```toml
[build]                         # open with sftp://build
host = "build.example.net"
port = 22                       # optional
user = "me"                     # optional
identity = "~/.ssh/id_ed25519"  # optional key file
password = "secret"             # optional, tried last; stored in plain text: prefer a key
```

Sign-in order: the bookmark's `identity`, then your SSH agent (Windows: OpenSSH agent, then
Pageant; Linux/macOS: `SSH_AUTH_SOCK`), then `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`, then the
bookmark's password. A password in the URL is refused.

## Host keys

Checked against `~/.ssh/known_hosts`, never trusted automatically. An unknown host is refused
with its SHA256 fingerprint and the exact line to add; a changed key is refused with
"HOST KEY CHANGED". Connect once with `ssh` to record a new host.

## Limitations

- Passphrase-protected key files ask for the passphrase (masked); it is kept in memory for the
  session only, never written anywhere. A wrong one asks again.
- No keyboard-interactive / 2FA prompts.
