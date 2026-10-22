from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).parents[1]))
from gui_apps import DesktopLauncher


class DesktopLauncherTests(unittest.TestCase):
    def test_only_configured_tools_can_be_launched(self):
        with tempfile.TemporaryDirectory() as temp:
            launcher=DesktopLauncher(temp,lambda tool:'/usr/bin/'+tool)
            with self.assertRaisesRegex(ValueError,'Unknown desktop'):
                launcher.open('sh')

    def test_missing_tool_has_installation_message(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError,'Burp Suite is not installed'):
                DesktopLauncher(temp,lambda tool:None).open('burpsuite')

    @patch('gui_apps.os.environ',{'DISPLAY':':0'})
    @patch('gui_apps.subprocess.Popen')
    def test_launch_uses_fixed_binary_and_reuses_running_instance(self,popen):
        process=Mock();process.wait.side_effect=subprocess.TimeoutExpired('wireshark',.6);process.poll.return_value=None;popen.return_value=process
        with tempfile.TemporaryDirectory() as temp:
            launcher=DesktopLauncher(temp,lambda tool:'/usr/bin/wireshark')
            self.assertIn('Opening Wireshark',launcher.open('wireshark')['message'])
            self.assertIn('already open',launcher.open('wireshark')['message'])
            self.assertEqual(popen.call_args.args[0],['/usr/bin/wireshark'])
            self.assertEqual(popen.call_count,1)

    @patch('gui_apps.os.environ',{})
    @patch('gui_apps.platform.system',return_value='Linux')
    def test_headless_session_reports_clear_error(self,system):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError,'No graphical desktop'):
                DesktopLauncher(temp,lambda tool:'/usr/bin/wireshark').open('wireshark')
