import unittest
import HtmlTestRunner
import subprocess
import os
from pathlib import Path


USERNAME = os.getenv('USERNAME', 'ubuntu')


def RunCmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.communicate()
    return p.returncode


class CourseOne(unittest.TestCase):

    def test_installed_pkgs(self):
        cmd = ['/usr/lib/update-notifier/apt-check']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output, error = proc.communicate()
        self.assertEqual(error.decode('ascii'), '0;0')


    def test_reboot(self):
        self.assertFalse(os.path.isfile('/var/run/reboot-required'))


class CourseTwo(unittest.TestCase):
    def setUp(self):
        self.SYMLINK_SRC = '/opt/vault-0.11.5/vault'
        self.SYMLINK_DEST = '/usr/local/bin/vault'
        self.SUBDIR = 'Downloads'
        self.CRONJOB_FILE = '/etc/cron.d/first_cronjob'

    def test_valid_logon(self):
        self.assertNotEqual(USERNAME, 'ubuntu')
        self.assertNotEqual(USERNAME, 'root')

    def test_homedir_exists(self):
        self.assertTrue(os.path.isdir(f"/home/{USERNAME}"))

    def test_subdir_exists(self):
        self.assertTrue(os.path.isdir(f"/home/{USERNAME}/{self.SUBDIR}"))

    def test_rsa_permissions(self):
        self.assertEqual(oct(os.stat(f"/home/{USERNAME}/.ssh/id_rsa").st_mode
                             & 0o777), '0o600')

    def test_symlink_exists(self):
        self.assertTrue(Path(self.SYMLINK_DEST).is_symlink())
        self.assertEqual(os.readlink(self.SYMLINK_DEST), self.SYMLINK_SRC)
        self.assertTrue(os.path.isfile(self.SYMLINK_SRC))


    def test_cronjob(self):
        self.assertTrue(os.path.isfile(self.CRONJOB_FILE))
        with open(self.CRONJOB_FILE, 'r') as f:
            content = f.read().strip()
        self.assertEqual(content, f"* * * * * {USERNAME} echo hello world")


class CourseThree(unittest.TestCase):
    def setUp(self):
        pass


    def test_libvirt_installed(self):
        cmd = ['dpkg', '-s', 'qemu-kvm']
        self.assertEqual(RunCmd(cmd), 0)

    def test_kvm_running(self):
        cmd = ['systemctl', 'is-active', '--quiet', 'libvirt-bin']
        self.assertEqual(RunCmd(cmd), 0)

    def test_vm_running(self):
        cmd = ['virsh', 'list', '--name' ]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output, err = p.communicate()
        self.assertTrue(len(output.split('\n')) > 0)

if __name__ == '__main__':
    unittest.main(testRunner=HtmlTestRunner.HTMLTestRunner())
