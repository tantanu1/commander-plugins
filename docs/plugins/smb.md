# SMB

SMB 2/3 client (Windows shares, Samba, NAS): browse, view, copy, move, rename and delete files on
file servers like a local folder, on Linux and macOS too. Pure Rust: no `libsmbclient` needed.

On Windows, `\\server\share` paths already work in any panel (Windows' own client and sign-in);
the plugin is for shares you want to open with other credentials from a bookmark.

## How to use

- **Ctrl+F** (the same dialog lists FTP, SFTP and SMB bookmarks) or type
  `smb://[user@]host[:port]/share/path`. Without a user, you sign in as guest (if allowed).
- `smb://host` lists the server's shares (hidden `$` shares are not listed: type
  `smb://host/C$`); `smb://` lists your bookmarks; `smb://<bookmark>` opens one.
- Domain accounts: `smb://CORP%5Cme@host` (`DOMAIN\user`), `smb://me%40corp.example@host`
  (`user@domain`) or the bookmark's `domain`.
- In Ctrl+F, **F7** adds (type SMB) and **F4** edits a bookmark (host, port, share, domain, user,
  optional password saved only when "Save password" is ticked).
- F3 / F4 / F5 / F6 / F7 / F8 work as on disk; F4 uploads every save.

## Setup: bookmarks (`smb.toml`)

Next to `config.toml` (env `COMMANDER_SMB_CONFIG` points elsewhere):

```toml
[nas]                  # open with smb://nas
host = "nas.local"
port = 445             # optional
share = "media"        # optional: the bookmark opens this share (else the share list)
user = "me"            # optional (empty = guest)
domain = "CORP"        # optional
password = "secret"    # optional, stored in plain text: prefer being asked
encrypt = true         # optional: refuse unencrypted sessions
```

Without `encrypt = true` (**Require encryption** in the form), a server that only *prefers*
encryption can be talked down to plain text by an attacker on the network path; signing still
protects the integrity of signed-in sessions, but guest sessions are neither signed nor encrypted.

Sign-in: NTLMv2 with the bookmark's password; without one, Commander asks (masked, memory only
for the session, never written anywhere; a wrong one asks again). A password in the URL is refused.

## Limitations

- SMB 2.0.2 to 3.1.1 (signing and encryption when the server asks); no SMB1.
- No Kerberos / single sign-on: NTLM user + password, or guest.
- A move (F6) between two shares of one server is refused: copy, then delete.
- Only the link flag of junctions / symlinks is shown (no hidden / read-only attributes).
