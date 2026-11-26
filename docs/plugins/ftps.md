# FTPS (explicit TLS)

FTP over explicit TLS (`AUTH TLS`). This plugin has no library of its own: it uses the `ftp`
plugin's, so installing it also installs `ftp`.

## How to use

- **Ctrl+F** (Net > FTP Connect): type `ftps://[user@]host[:port]/path` or pick a bookmark with
  `tls = true`.
- Everything else works as with the FTP plugin: F3 / F4 / F5 / F6 / F7 / F8, resume.

## Setup

Bookmarks are shared with FTP in `ftp.toml` (see the FTP plugin): set `tls = true` on a bookmark.

## Limitations

- The server certificate must be valid: self-signed servers fail.
- No implicit FTPS (port 990). Passive mode only.
- Uninstalling `ftp` breaks `ftps`: keep both.
