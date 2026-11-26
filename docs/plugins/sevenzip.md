# 7-Zip archives

Opens RAR, ISO, CAB, ARJ, LZH, WIM, split (`.001`) and encrypted archives like folders, using
**your own installed 7-Zip**. Nothing else is bundled.

## Setup

- Windows: install 7-Zip from 7-zip.org.
- Linux / macOS: put `7zz` or `7z` on your PATH.
- Env `COMMANDER_7Z` can point at the 7-Zip program directly.

## How to use

- Enter (or Ctrl+PgDn) on a `.rar`, `.iso`, `.cab`, `.arj`, `.lzh`, `.wim` or `.001` file opens
  it. Zip, 7z and tar open with Commander's built-in reader; this plugin steps in where that
  reader can't (for example encrypted items).
- Password-protected archives ask for the password. It is kept in memory only, never in a path,
  log or config file.
- 7z, zip, tar and wim archives can be written to (copy in, delete, rename); Alt+F5 can pack to
  `.7z`. Every file added is tested before a move deletes its source.

## Config keys

| Setting | Meaning |
|---|---|
| `COMMANDER_7Z` (env) | Full path of the 7-Zip program to use |

## Limitations

- RAR is extract-only.
- Without 7-Zip installed the plugin loads but cannot open anything (it says so).
