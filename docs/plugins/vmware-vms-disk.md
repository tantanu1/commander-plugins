# VMware VMs

Browse **and change** the files inside your running VMware virtual machines (Workstation, Player,
Fusion) like a local folder: view, copy in and out, edit, rename, create folders, delete. It goes
through VMware Tools in the guest, so the guest needs no network, share or SSH server.

## How to use

- Type `vmware://` in the path bar: one folder per **running** VM (named after its display name),
  plus `<vm>.connect.txt`.
- Enter a VM folder: Commander asks for the **guest** login. With a user set in `vmware.toml`
  (or typed as `vmware://user@<vm>`) it asks only for the password; otherwise type
  `user:password` (for example `Administrator:secret`, or `CORP\me:secret` for a domain account).
  The login stays in memory only until you quit; it is never written to disk, logs or settings.
  A wrong login asks again.
- Windows guests show their drives (`C`, `D`, ... = `C:\`, `D:\`); Linux guests show `/`.
- F3 / F4 / F5 / F6 / F7 / F8 work as on disk. F4 uploads every save.
- `<vm>.connect.txt` (F3): the guest's IP address and the `sftp://<user>@<ip>/` and
  `smb://<user>@<ip>/` addresses that open the same guest through Commander's SFTP / SMB plugins
  (faster for big files; needs an SSH server or file sharing in the guest). Type one in the path
  bar. It also says which backend (VIX or vmrun) is in use, and why VIX is not.

The **vm** drive button (drive bar, Alt+F1 / Alt+F2) opens `vmware://` too.

## Encrypted VMs (vTPM / Windows 11)

Workstation encrypts every VM that has a virtual TPM (Windows 11 needs one), and VMs can be
encrypted on their own too. Commander sees it in the `.vmx` (it only checks that the
`encryption.keySafe` key is there; its value is never read or shown) or from VMware's answer.

- Opening such a VM asks first for the **VM encryption password** (the one Workstation asks
  when you power the VM on), then the **guest login**. Two prompts, clearly named.
- A wrong VM password asks again ("encrypted VM: enter the VM password", with VMware's own
  error text and code); a wrong guest login asks only for the login again.
- The VM password stays in memory until Commander quits (never written anywhere, wiped on
  exit). With the vmrun fallback it is passed as `-vp`, so like the guest password it is on
  vmrun's command line while it runs.
- `<vm>.connect.txt` says `Encrypted VM: yes`; when the VM cannot be opened it shows VMware's
  error text and code (`VIX error ...`): quote it when you report a problem.

## Requirements

- VMware Workstation, Player or Fusion on this computer, the VM **powered on**, and **VMware
  Tools** (or open-vm-tools) running in the guest.
- A guest account (Windows or Linux guests; other guest systems cannot log in).
- Best: the **VMware VIX** library (Windows: the VIX SDK, installed to
  `C:\Program Files (x86)\VMware\VMware VIX`; Linux: `libvixAllProducts.so`; Fusion: inside the
  app). Without it the plugin falls back to `vmrun` (part of Workstation / Fusion).
- Not supported: ESXi / vCenter hosts (use SFTP / SMB to those guests), suspended or powered-off
  VMs (they are not listed; Commander never starts, stops or changes a VM).

## Setup (optional): `vmware.toml`

Next to `config.toml` (env `COMMANDER_VMWARE_CONFIG` points elsewhere):

```toml
product = "ws"          # ws | player | fusion (default: ws, fusion on macOS)
backend = "auto"        # auto (VIX, else vmrun) | vix | vmrun
vix = 'C:\Program Files (x86)\VMware\VMware VIX\Workstation-17.0.0\64bit\vix.dll'  # tried first
vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
user = "me"             # guest user for every VM
drives = "CD"           # Windows guests: drives to show (default: probe C..Z)

[users]
"Windows 11" = "Administrator"   # guest user per VM (its name in vmware://)
```

## Speed and limits

- Each file is copied whole (no partial reads): a guest file is first copied to a private temp
  folder on this computer (owner-only, removed right after), then shown or copied; an upload is
  copied to a temp name next to the target, then renamed in place. VIX copies run at roughly
  2-25 MB/s; for big transfers use the SFTP / SMB address from `<vm>.connect.txt`.
- Cancel stops waiting at once; a copy already handed to VMware finishes in the background and
  its temp file is removed then. An upload cancelled before its final copy leaves nothing in the
  guest; the final copy + rename itself is not interruptible.
- **vmrun fallback**: every action logs in again, and the **guest password is on vmrun's command
  line** while it runs (other local users / processes may see it). Listings have no sizes or dates,
  one extra vmrun run per entry tells folders from files, and a file's size is learnt by copying
  it: slow, and copying a whole folder out fails on the unknown sizes. Install VIX to avoid all of
  this.
- With the VIX SDK on Windows, the 64-bit wrapper's `vixwrapper-config.txt` may name a
  Workstation version folder that is not installed; the plugin then loads the newest
  `Workstation-*\64bit\vix.dll` itself, and falls back to vmrun if that does not connect.
- A replace (overwrite) writes a **new** file: the old file's permissions, owner and ACL are not
  kept (Linux: an executable loses `+x`; Windows: the folder's inherited ACL applies). Linux
  guests: new file to a temp name, then one rename over the old (atomic). Windows guests: old
  file renamed aside, new renamed in, old deleted; if that fails the old file is put back, and
  if even that fails the error names where the old file and the new data were left.
- Windows guests refuse names with `: * ? " < > |` or ending in `.` / space (`:` would write an
  NTFS alternate data stream).
- vmrun output is read as UTF-8: with the vmrun fallback on Windows, non-ASCII guest names may
  show garbled (VIX has no such problem).
- With the vmrun fallback the login prompt itself says that the password will be visible to
  other local processes.

## Test it (manual, with your own VM)

1. Power on a VM with VMware Tools. Type `vmware://`: the VM is listed; F3 on
   `<vm>.connect.txt` shows its IP and `Backend: VIX (...)`.
2. Enter the VM, type `user:password` of a guest account. A wrong password asks again.
3. Windows guest: `C` lists `C:\`. Linux guest: `/` is listed.
4. F7 a folder `cmdr-test`, F5 a small and a 100 MB file into it, F3 one, F4-edit and save the
   small one, Shift+F6 rename, F5 back out to a local folder and compare, F8 everything.
5. Start a big F5 and cancel it: nothing new appears in the guest.
6. With `backend = "vmrun"` in `vmware.toml`, repeat 1-4 (slow; folder copy-out fails, see above).
