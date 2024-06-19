from ssh_known_hosts_edit import SSHKnownHostsEdit

TEST_KEY_1 = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
TEST_KEY_2 = ('ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt'
              '5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=')

TEST_HOSTNAME = 'github.com'
TEST_OTHER_HOSTNAME = 'gitlab.com'
TEST_HOSTNAME_HASHED = '|1|w42Ofu6QxlTmQ2Vsf7EeE1F5fmk=|01rlazBSQwY8mH1DhOZZ/54xahU='


def _assert_file_content(file_name: str, content: str):
    with open(file_name) as f:  # noqa: PTH123
        assert f.read().strip() == content.strip()


def _write_file_content(file_name: str, content: str):
    with open(file_name, 'w') as f:  # noqa: PTH123
        f.write(content)


def test_ssh_known_hosts_edit_add_1a(known_hosts_filename):
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    # non existing file
    assert not edit.SSH_KNOWN_HOSTS.exists()
    assert not edit.SSH_KNOWN_HOSTS.is_file()
    assert edit.add_to_known_hosts(TEST_HOSTNAME, TEST_KEY_1) is True
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME} {TEST_KEY_1}\n"
    )


def test_ssh_known_hosts_edit_add_1b(known_hosts_filename):
    # file with existing content
    _write_file_content(known_hosts_filename, f"{TEST_HOSTNAME} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.add_to_known_hosts(TEST_HOSTNAME, TEST_KEY_2) is True
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME} {TEST_KEY_1}\n"
        f"{TEST_HOSTNAME} {TEST_KEY_2}\n"
    )


def test_ssh_known_hosts_edit_add_1c(known_hosts_filename):
    # empty file
    _write_file_content(known_hosts_filename, "")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.add_to_known_hosts(TEST_HOSTNAME, TEST_KEY_1) is True
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME} {TEST_KEY_1}\n"
    )


def test_ssh_known_hosts_edit_add_1d(known_hosts_filename):
    # file with existing same content
    _write_file_content(known_hosts_filename, f"{TEST_HOSTNAME} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.add_to_known_hosts(TEST_HOSTNAME, TEST_KEY_1) is False
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME} {TEST_KEY_1}\n"
    )


def test_ssh_known_hosts_edit_add_1e(known_hosts_filename):
    # file with existing hashed content
    _write_file_content(known_hosts_filename, f"{TEST_HOSTNAME_HASHED} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.add_to_known_hosts(TEST_HOSTNAME, TEST_KEY_2) is True
    # Note: the hashed hostname will be based on a random hash, so this test can't predict it

    with open(known_hosts_filename) as f:  # noqa: PTH123
        actual_content = f.read()
        assert actual_content.startswith(f"{TEST_HOSTNAME_HASHED} {TEST_KEY_1}\n|")
        assert actual_content.endswith(f" {TEST_KEY_2}\n")


def test_ssh_known_hosts_edit_add_1f(known_hosts_filename):
    # file with existing same hashed content
    _write_file_content(known_hosts_filename, f"{TEST_HOSTNAME_HASHED} {TEST_KEY_1}\n")
    edit = SSHKnownHostsEdit(known_hosts_file_location=known_hosts_filename)
    assert edit.add_to_known_hosts(TEST_HOSTNAME, TEST_KEY_1) is False
    _assert_file_content(
        known_hosts_filename,
        f"{TEST_HOSTNAME_HASHED} {TEST_KEY_1}\n"
    )
