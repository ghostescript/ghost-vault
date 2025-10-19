# ghost-vault
Create password-protected hidden directories (ghost vaults) and manage encrypted files.

<br>

# Installation 
```bash
git clone https://github.com/ghostescript/ghost-vault
cd ghost-vault
python ghost.vault.py
```

<br>

# Examples

* create

> Create a password protected directory or vault to store encrypted files.
```bash
python ghost.vault.py create vault_name
```

* add

> Encrypt and move a file to a vault (include the full path of the file).
```bash
python ghost.vault.py add vault_name item_to_add
```

* list

> List encrypted files in a vault.
```bash
python ghost.vault.py list vault_name
```

* retrieve

> Decrypt and move a file from a vault to a chosen path or the current directory by default.
```bash
python ghost.vault.py retrieve vault_name encrypted_filename output_path
```

<br>

> Decrypts file to tool directory by default from a specified vault. 
```bash
python ghost.vault.py retrieve vault_name encrypted_filename
```

* help

> Help message flag can be used with any argument for more information or display the main help message and exit.
```bash
python ghost.vault.py retrieve -h
```
> Main help message and exit.
```bash
python ghost.vault.py --help
```

<br>

# Update On
`` Oct 18, 2025``

<br>

