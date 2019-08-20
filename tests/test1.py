import unittest
import HtmlTestRunner
import subprocess
import os
from pathlib import Path
import nmap
import pysftp
import dns.resolver
from requests_html import HTMLSession
from smtplib import SMTP

USERNAME = os.getenv('USERNAME', 'ubuntu')
template_args = {
    "user": USERNAME,

}


def RunCmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.communicate()
    return p.returncode


class Lektion1_uppg1(unittest.TestCase):

    def test_installed_pkgs(self):
        cmd = ['/usr/lib/update-notifier/apt-check']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        output, error = proc.communicate()
        self.assertEqual(error.decode('ascii'), '0;0')


    def test_reboot(self):
        self.assertFalse(os.path.isfile('/var/run/reboot-required'))


class Lektion1_uppg2(unittest.TestCase):
    def setUp(self):
        self.SYMLINK_SRC = f'/home/{USERNAME}/linuxserver2/reports'
        self.SYMLINK_DEST = '/var/www/html/reports'
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
        self.assertTrue(os.path.isdir(self.SYMLINK_SRC))


    def test_cronjob(self):
        self.assertTrue(os.path.isfile(self.CRONJOB_FILE))
        with open(self.CRONJOB_FILE, 'r') as f:
            content = f.read().strip()
        self.assertTrue("*/5 8-17 * * 1-5" in content)


class Lektion2_uppg1(unittest.TestCase):
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
        self.assertTrue(len(str(output).split('\n')) > 0)


class Labb(unittest.TestCase):
    """
      scan kvm vm's for running services
      [ ftp, smtp, http ]
      'product' is found with nmap -sV -p <port> <ip>
    """

    """
    def setUp(self):
        self.nm = nmap.PortScanner()
        self.nm.scan(hosts='192.168.122.2-254', ports='21,25,53,80,389')
        self.hosts = {}
        for host in self.nm.all_hosts():
            if self.nm[host]['tcp'][21]['state'] == 'open':
                self.hosts['ftp'] = host
            if self.nm[host]['tcp'][25]['state'] == 'open':
                self.hosts['smtp'] = host
            if self.nm[host]['tcp'][53]['state'] == 'open':
                if 'dnsmasq' not in self.nm[host]['tcp'][53]['product']:
                    self.hosts['dns'] = host
            if self.nm[host]['tcp'][80]['state'] == 'open':
                self.hosts['http'] = host
            if self.nm[host]['tcp'][389]['state'] == 'open':
                self.hosts['ldap'] = host


    def test_vm_ftp(self):
        self.assertTrue('ftp' in self.hosts)
        self.assertTrue('OpenSSH' in self.nm[self.hosts['ftp']]['tcp'][21]['product'])
        with pysftp.Connection(host=self.nm[self.hosts['ftp']]['addresses']['ipv4'],
                                port=21,
                                username=USERNAME,
                                private_key=f"/home/{USERNAME}/.ssh/id_rsa") as ftp:
            self.assertTrue(ftp.isfile('ftp_file'))

    def test_vm_dns(self):
        self.assertTrue('dns' in self.hosts)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [self.nm[self.hosts['dns']]['addresses']['ipv4']]
        try:
            answer = resolver.query(f'smtp.{USERNAME}.local', 'A')
            self.assertTrue(len(answer) > 0)
        except dns.resolver.NXDOMAIN:
            self.assertTrue(False)



    def test_vm_smtp(self):
        self.assertTrue('smtp' in self.hosts)
        self.assertTrue('smtp' in self.nm[self.hosts['smtp']]['tcp'][25]['product'])
        with SMTP(self.nm[self.hosts['smtp']]['addresses']['ipv4'] as smtp:
            session = smtp.connect(host=self.nm[self.hosts['smtp']]['addresses']['ipv4'], port=25)
            self.assertTrue(session[0] == 220)


    def test_vm_http(self):
        self.assertTrue('http' in self.hosts)
        self.assertTrue('http' in self.nm[self.hosts['http']]['tcp'][80]['product'])

        session = HTMLSession()
        r = session.get(f"http://{self.nm[self.hosts['http']]['addresses']['ipv4']}")
        self.assertTrue(f"{USERNAME}" in r.html.text)
    """


if __name__ == '__main__':
    unittest.main(testRunner=HtmlTestRunner.HTMLTestRunner(
        combine_reports=True,
        report_name="report", add_timestamp=False,
        template='template.j2', template_args=template_args))
