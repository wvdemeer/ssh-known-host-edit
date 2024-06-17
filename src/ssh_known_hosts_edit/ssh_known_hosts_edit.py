"""OpenSSH known_hosts file edit tool."""

import os
import stat
import tempfile
from pathlib import Path
from subprocess import DEVNULL, PIPE, Popen
from typing import Optional


class SSHKnownHostsEditException(Exception):
    """Something went wrong trying to edit ~/.ssh/known_hosts."""


class NoSSHKnownHostsFileException(SSHKnownHostsEditException):
    """~/.ssh/known_hosts does not exist, and cannot be created."""


class NoSSHKeygenException(SSHKnownHostsEditException):
    """OpenSSH's ssh-keygen tool is not found."""


class SSHKnownHostsEdit:
    """Helper class to edit ~/.ssh/known_hosts."""

    def __init__(self, *, known_hosts_file_location: Optional[str] = None):
        self.SSH_KNOWN_HOSTS: Path = self._find_known_hosts(known_hosts_file_location)
        self.SSH_KEYGEN: Path = self._find_ssh_keygen()
        self.IS_KNOWN_HOSTS_HASHED = self._is_known_hosts_hashed()

    def _find_known_hosts(self, known_hosts_file_location: Optional[str]) -> bool:
        if known_hosts_file_location:
            return Path(known_hosts_file_location)
        # TODO: more complex logic needed?
        return Path.home() / ".ssh" / "known_hosts"

    def _find_ssh_keygen(self) -> bool:
        try:
            paths = os.environ.get("PATH", "").split(os.pathsep)
            for p in ["/usr/bin", "/bin", "/usr/local/bin"]:
                if p not in paths and Path(p).exists():
                    paths.append(p)

            for d in paths:
                if not d:
                    continue
                path = Path(d) / "ssh-keygen"
                if path.exists() and not path.is_dir() and (
                        path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                    return path
        except OSError as e:
            raise SSHKnownHostsEditException from e

        raise NoSSHKeygenException

    def _ensure_known_hosts_parent_exists(self):
        parent = self.SSH_KNOWN_HOSTS.parent
        if not parent.is_dir() and not parent.exists():
            # We only try to create the parent. Not the parent's parent.
            try:
                parent.mkdir()
                parent.chmod(0o700)
            except OSError as e:
                raise SSHKnownHostsEditException from e

    def _is_known_hosts_hashed(self) -> bool:
        # From `man sshd` section `SSH_KNOWN_HOSTS FILE FORMAT`:
        #     Alternately, hostnames may be stored in a hashed form which hides host names and addresses should the
        #     file’s contents be disclosed.  Hashed hostnames start with a ‘|’ character.  Only one hashed hostname may
        #     appear on a single line and none of the above negation or wildcard operators may be applied.
        if not self.SSH_KNOWN_HOSTS.is_file():
            # The known hosts file does not yet exist. So we'd have to check the SSH config to know.
            # We fall back to not hashed instead.
            return False

        try:
            with self.SSH_KNOWN_HOSTS.open() as f:
                for line in f:
                    if line.startswith("|"):
                        # Hashed files support non hashed hosts.
                        # A single hashed line means we'll assume hashed hostnames are prefered.
                        return True
        except OSError as e:
            raise SSHKnownHostsEditException from e

        return False

    def _ssh_keygen_h(self, host: str, public_key: str) -> str:
        # This uses ssh-keygen -H to hash the line
        # From `man ssh-keygen`:
        #    ssh-keygen -H [-f known_hosts_file]
        #        -H      Hash a known_hosts file.  This replaces all hostnames and addresses with hashed representations
        #                within the specified file; the original content is moved to a file with a .old suffix.  These
        #                hashes may be used normally by ssh and sshd, but they do not reveal identifying information
        #                should the file's contents be disclosed.  This option will not modify existing hashed hostnames
        #                and is therefore safe to use on files that mix hashed and non-hashed names.
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_file = Path(tmp_dir) / 'known_hosts_line'
            with tmp_file.open('w') as f:
                f.write(f"{host} {public_key}\n")
            command = [str(self.SSH_KEYGEN), '-H', '-f', str(tmp_file)]
            try:
                with Popen(command, stdout=DEVNULL, stderr=DEVNULL) as proc:  # noqa: S603
                    return_code = proc.wait(timeout=10)  # noqa: F841
                with tmp_file.open() as f:
                    return f.read().strip()
            except OSError as e:
                raise SSHKnownHostsEditException from e

    def _ssh_keygen_f(self, host: str) -> list[str]:
        # From `man ssh-keygen`:
        #    ssh-keygen -F hostname [-lv] [-f known_hosts_file]
        #        -F hostname | [hostname]:port
        #                Search  for  the  specified  hostname (with optional port number) in a known_hosts file,
        #                listing any occurrences found.  This option is useful to find hashed host names or addresses
        #                and may also be used in conjunction with the -H option to print found keys in a hashed format.
        command = [str(self.SSH_KEYGEN), '-F', host, '-f', str(self.SSH_KNOWN_HOSTS)]
        try:
            with Popen(command, stdout=PIPE, stderr=DEVNULL) as proc:  # noqa: S603
                # output is in this form:
                # # Host github.com found: line 1500
                # github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
                # # Host github.com found: line 1501
                # github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEe...

                res = []
                for b in proc.stdout:
                    line = b.decode("utf-8")
                    if line.strip().startswith('#'):
                        continue
                    res.append((' '.join(line.split(" ")[1:])).strip())
                return_code = proc.wait(timeout=10)  # noqa: F841
                return res
        except OSError as e:
            raise SSHKnownHostsEditException from e

    def _ssh_keygen_r(self, host: str):
        # From `man ssh-keygen`:
        #    ssh-keygen -R hostname [-f known_hosts_file]
        #       -R hostname | [hostname]:port
        #           Removes all keys belonging to the specified hostname (with optional port number) from a known_hosts
        #           file. This option is useful to delete hashed hosts (see the -H option above).
        command = [str(self.SSH_KEYGEN), '-R', host, '-f', str(self.SSH_KNOWN_HOSTS)]
        try:
            with Popen(command, stdout=DEVNULL, stderr=DEVNULL) as proc:  # noqa: S603
                return_code = proc.wait(timeout=10)  # noqa: F841
        except OSError as e:
            raise SSHKnownHostsEditException from e

    def _is_host_key_known(self, host: str, public_key: str) -> bool:
        keys = self._ssh_keygen_f(host)
        return public_key in keys

    def _normalize_key(self, public_key: str) -> str:
        """Remove comments from a public key line."""
        return ' '.join(public_key.split(" ")[:2])

    def _add_known_hosts_line(self, line: str) -> str:
        self._ensure_known_hosts_parent_exists()
        with self.SSH_KNOWN_HOSTS.open(mode='a') as f:
            f.write(line + "\n")

    def add_to_known_hosts(self, host: str, public_key: str) -> bool:
        """Add the public key for a host to ~/.ssh/known_hosts (if it was not yet present).

        @param host: The host to add the public key for.
        @param public_key: The public key to add to the known_hosts file. In Openssh public key format.
                           May include comments, which will be removed.
        @return: True if the public key was added to the known_hosts file.
        """
        public_key = self._normalize_key(public_key)
        if self._is_host_key_known(host, public_key):
            return False
        if self.IS_KNOWN_HOSTS_HASHED:
            hashed_line = self._ssh_keygen_h(host, public_key)
            self._add_known_hosts_line(hashed_line)
        else:
            self._add_known_hosts_line(f"{host} {public_key}")
        return True

    def remove_from_known_hosts(self, host: str) -> bool:
        """Remove the keys for a specific host from ~/.ssh/known_hosts (if they are present).

        @param host: The host to remove the keys for.
        @return: True if the public key was removed from the known_hosts file.
        """
        if not self.SSH_KNOWN_HOSTS.is_file():
            return False
        orig_size = self.SSH_KNOWN_HOSTS.stat().st_size
        self._ssh_keygen_r(host)
        new_size = self.SSH_KNOWN_HOSTS.stat().st_size
        return orig_size > new_size
