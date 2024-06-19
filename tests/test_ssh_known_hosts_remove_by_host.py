from pathlib import Path

from ssh_known_hosts_edit import SSHKnownHostsEdit

TEST_KEY_1 = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
TEST_KEY_2 = ('ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt'
              '5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=')

TEST_HOSTNAME = 'github.com'
TEST_OTHER_HOSTNAME = 'gitlab.com'
TEST_HOSTNAME_HASHED = '|1|w42Ofu6QxlTmQ2Vsf7EeE1F5fmk=|01rlazBSQwY8mH1DhOZZ/54xahU='
TEST_HOSTNAME_HASHED_ALT = '|1|52d0KBGaA6SvZDyKVsoZ7Tq9hI0=|euXcjP63oIJN93jcCfhgKY6kdVw='
TEST_OTHER_HOSTNAME_HASHED = '|1|pPx5FVnJqJA3xgEXdoYJhOiu4mk=|GnGtO4VhG/WuyIvRJ0yxDUYZsDo='


def _assert_file_content(file_name: str, content: str):
    with open(file_name) as f:  # noqa: PTH123
        assert f.read().strip() == content.strip()


def _write_file_content(file_name: str, content: str):
    with open(file_name, 'w') as f:  # noqa: PTH123
        f.write(content)

def test_ssh_known_hosts_edit_remove_1a(known_hosts_filename):
    # no file
    assert Path(known_hosts_filename).exists() is False
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert Path(known_hosts_filename).exists() is False
    assert edit.remove_from_known_hosts_by_host(TEST_HOSTNAME) is False
    assert Path(known_hosts_filename).exists() is False


def test_ssh_known_hosts_edit_remove_1b(known_hosts_filename):
    # empty file
    _write_file_content(known_hosts_filename, "")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.remove_from_known_hosts_by_host(TEST_HOSTNAME) is False
    _assert_file_content(
        known_hosts_filename,
        ""
    )


def test_ssh_known_hosts_edit_remove_1c(known_hosts_filename):
    # file with existing other content
    _write_file_content(known_hosts_filename, f"{TEST_HOSTNAME} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.remove_from_known_hosts_by_host(TEST_OTHER_HOSTNAME) is False
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME} {TEST_KEY_1}\n"
    )


def test_ssh_known_hosts_edit_remove_1d(known_hosts_filename):
    # file with existing same content
    _write_file_content(known_hosts_filename, f"{TEST_HOSTNAME} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.remove_from_known_hosts_by_host(TEST_HOSTNAME) is True
    _assert_file_content(
        known_hosts_filename,
        ""
    )


def test_ssh_known_hosts_edit_remove_1e(known_hosts_filename):
    # file with existing same content on multiple lines
    _write_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME} {TEST_KEY_1}\n"
        f"{TEST_HOSTNAME} {TEST_KEY_2}\n"
        f"{TEST_OTHER_HOSTNAME} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.remove_from_known_hosts_by_host(TEST_HOSTNAME) is True
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_OTHER_HOSTNAME} {TEST_KEY_1}\n"
    )


def test_ssh_known_hosts_edit_remove_1f(known_hosts_filename):
    # file with existing other content hashed
    _write_file_content(known_hosts_filename, f"{TEST_HOSTNAME_HASHED} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.remove_from_known_hosts_by_host(TEST_OTHER_HOSTNAME) is False
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME_HASHED} {TEST_KEY_1}\n"
    )


def test_ssh_known_hosts_edit_remove_1g(known_hosts_filename):
    # file with existing same content hashed
    _write_file_content(known_hosts_filename, f"{TEST_HOSTNAME_HASHED} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.remove_from_known_hosts_by_host(TEST_HOSTNAME) is True
    _assert_file_content(
        known_hosts_filename,
        ""
    )

def test_ssh_known_hosts_edit_remove_1h(known_hosts_filename):
    # file with existing same and other content hashed and not hashed
    _write_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME_HASHED} {TEST_KEY_1}\n"
        f"{TEST_HOSTNAME_HASHED} {TEST_KEY_2}\n"
        f"{TEST_HOSTNAME_HASHED_ALT} {TEST_KEY_1}\n"
        f"{TEST_HOSTNAME_HASHED_ALT} {TEST_KEY_2}\n"
        f"{TEST_OTHER_HOSTNAME_HASHED} {TEST_KEY_1}\n"
        f"{TEST_OTHER_HOSTNAME_HASHED} {TEST_KEY_2}\n"
        f"{TEST_HOSTNAME} {TEST_KEY_1}\n"
        f"{TEST_HOSTNAME} {TEST_KEY_2}\n"
        f"{TEST_OTHER_HOSTNAME} {TEST_KEY_1}\n"
        f"{TEST_OTHER_HOSTNAME} {TEST_KEY_2}\n"
    )
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.remove_from_known_hosts_by_host(TEST_HOSTNAME) is True
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_OTHER_HOSTNAME_HASHED} {TEST_KEY_1}\n"
        f"{TEST_OTHER_HOSTNAME_HASHED} {TEST_KEY_2}\n"
        f"{TEST_OTHER_HOSTNAME} {TEST_KEY_1}\n"
        f"{TEST_OTHER_HOSTNAME} {TEST_KEY_2}\n"
    )
