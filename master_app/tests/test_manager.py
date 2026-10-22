import importlib.util
from pathlib import Path
import unittest
import sys
sys.path.insert(0, str(Path(__file__).parents[1]))
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('manager', Path(__file__).parents[1] / 'run.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ManagerTests(unittest.TestCase):
    @patch.object(m, 'locate', return_value='/usr/bin/nmap')
    @patch.object(m, 'capture')
    def test_apt_update_only_upgrades_owned_package(self, capture, locate):
        capture.side_effect = ['Candidate: 7.98', 'nmap: /usr/bin/nmap']
        kind, cmd = m.plan('nmap', 'update', {'manager': 'apt-get'})
        self.assertEqual(kind, 'admin')
        self.assertEqual(cmd, ['apt-get', 'install', '-y', '--only-upgrade', 'nmap'])

    @patch.object(m, 'locate', return_value='/custom/nmap')
    @patch.object(m, 'capture', return_value='')
    def test_unmanaged_removal_is_rejected(self, capture, locate):
        with self.assertRaisesRegex(ValueError, 'not owned'):
            m.plan('nmap', 'remove', {'manager': 'apt-get'})

    @patch.object(m, 'locate', return_value=None)
    @patch.object(m, 'capture', return_value='Candidate: (none)')
    def test_unavailable_package_is_explained(self, capture, locate):
        with self.assertRaisesRegex(ValueError, 'No package candidate'):
            m.plan('anonsurf', 'install', {'manager': 'apt-get'})

    @patch.object(m, 'locate', return_value=None)
    def test_windows_uses_exact_winget_id(self, locate):
        kind, cmd = m.plan('nmap', 'install', {'manager': 'winget'})
        self.assertEqual(kind, 'command')
        self.assertIn('Insecure.Nmap', cmd)
        self.assertIn('--exact', cmd)

    @patch.object(m, 'locate', return_value=None)
    def test_unsupported_windows_tool_is_explained(self, locate):
        with self.assertRaisesRegex(ValueError, 'No supported native installer'):
            m.plan('anonsurf', 'install', {'manager': 'winget'})

    @patch.object(m, 'locate', return_value='/usr/bin/nmap')
    def test_existing_tool_is_not_reinstalled(self, locate):
        with self.assertRaisesRegex(ValueError, 'Already installed'):
            m.plan('nmap', 'install', {'manager': 'apt-get'})


if __name__ == '__main__':
    unittest.main()
