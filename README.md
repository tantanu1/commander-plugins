# Commander plugins

Open-source (MIT) plugins for [Commander](https://github.com/tantanu1/public-commander), a fast,
modern Total Commander-style file manager for Windows, Linux and macOS, plus the plugin SDK.

A Commander plugin is a native library (C ABI v1, [sdk/include/commander_plugin.h](sdk/include/commander_plugin.h))
or a stdio program with a `plugin.toml` manifest. Most plugins here are *vfs* plugins: a remote
or special file system shows up as a normal panel (copy, move, view, edit, delete work as on disk).

| Plugin | Folder | What it does |
|---|---|---|
| S3 | [plugins/s3](plugins/s3) | Amazon S3 and S3-compatible storage (MinIO, R2, ...) as `s3://` |
| FTP | [plugins/ftp](plugins/ftp) | FTP client: browse and copy files on FTP servers like a local folder |
| FTPS | [plugins/ftps](plugins/ftps) | FTP over explicit TLS (`ftps://`); uses the ftp plugin's library |
| SFTP | [plugins/sftp](plugins/sftp) | SFTP (SSH) client with key, agent and known_hosts checks |
| SMB | [plugins/smb](plugins/smb) | SMB 2/3 client (Windows shares, Samba, NAS), pure Rust |
| 7-Zip | [plugins/sevenzip](plugins/sevenzip) | rar, iso, cab, 7z, encrypted archives through your installed 7-Zip |
| VMware VMs | [plugins/vmware](plugins/vmware) | Files inside running VMware Workstation / Player / Fusion VMs |

[plugins/abi](plugins/abi) is the shared Rust crate (`commander_plugin_abi`): the ABI types and
glue the Rust plugins use. [sdk/](sdk) has examples in C, Rust and Python; the plugin
developer guide is [docs/PLUGIN-DEV.md](docs/PLUGIN-DEV.md). Each plugin's user doc is in
[docs/plugins/](docs/plugins).

## Build

Rust stable (edition 2024):

```sh
cargo build --release          # target/release: the plugin libraries (.dll / .so / .dylib)
cargo test
cargo clippy --all-targets -- -D warnings
```

A plugin folder is `plugins/<name>/plugin.toml` plus the built library next to it
(`ftps` uses the `ftp` library: install both).

Release zips: `bash scripts/package.sh <target> <version> dist` after
`cargo build --release --locked --target <target>`.

## Install

Official builds: the [releases](https://github.com/tantanu1/commander-plugins/releases) of this
repo. Per target (`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`,
`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`):

- `<id>-<plugin version>-<target>.zip`: one plugin (`ftps` also holds `ftp`, whose library it uses).
- `commander-plugins-<version>-<target>.zip`: all plugins.

In Commander: Options > Plugins > Browse registry, or drop a zip on a panel. Details:
[docs/INSTALL-PLUGINS.md](docs/INSTALL-PLUGINS.md).

## Releases

A tag `vX.Y.Z` is the Commander version this repo was exported from (= `version` in
[Cargo.toml](Cargo.toml)); each plugin's own version is in its `plugin.toml` and in its zip
name. Pushing the tag runs [.github/workflows/release.yml](.github/workflows/release.yml):
release build per target, [scripts/package.sh](scripts/package.sh) packs the zips, and they are
published as the GitHub Release of that tag.

## Contributing

Issues and pull requests are welcome. For now only the owner merges. By contributing you agree
that your contribution is licensed under the MIT license of this repo.

This repo is exported from the Commander source tree; changes are applied there and synced here.

## License

[MIT](LICENSE). The SDK example [sdk/examples/hello-python](sdk/examples/hello-python) is public
domain (CC0). Commander itself is not part of this repo.
