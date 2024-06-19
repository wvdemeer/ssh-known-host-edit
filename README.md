# OpenSSH known_hosts file edit tool

This is a helper class to edit `~/.ssh/known_hosts`.
It mostly calls the appropriate `ssh-keygen` commands.
It automatically hashes hostnames if there are already hashed hostnames in  `~/.ssh/known_hosts`.

Usage:

```python
from ssh_known_hosts_edit import SSHKnownHostsEdit

edit = SSHKnownHostsEdit()
edit.add_to_known_hosts('github.com',
                        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl')
edit.add_to_known_hosts('github.com',
                        'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=')
edit.remove_from_known_hosts_by_host('github.com')
```
