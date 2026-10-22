import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parents[1]))
import network_manager as network


class NetworkTests(unittest.TestCase):
    @patch.object(network.platform, 'system', return_value='Linux')
    @patch.object(network, 'managed_interface', return_value=None)
    @patch.object(network, 'default_interface', return_value=None)
    @patch.object(network, 'find', return_value=None)
    def test_missing_tools_are_explicit(self, *mocks):
        state=network.status()
        self.assertEqual(state['anonsurf']['state'], 'not-installed')
        self.assertEqual(state['macchanger']['state'], 'not-installed')
        self.assertFalse(state['anonsurf']['installed'])

    @patch.object(network.platform, 'system', return_value='Linux')
    @patch.object(network, 'managed_interface', return_value=None)
    @patch.object(network, 'default_interface', return_value=None)
    @patch.object(network, 'find', side_effect=lambda p: '/usr/bin/anonsurf' if p=='anonsurf' else None)
    @patch.object(network, 'read_command', return_value=(json.dumps({'anonsurf_active':False,'tor_active':True,'dns_state':'clearnet'}),0,''))
    def test_tor_running_does_not_mean_anonsurf_active(self, *mocks):
        state=network.status()
        self.assertEqual(state['anonsurf']['state'], 'inactive')
        self.assertTrue(state['anonsurf']['tor'])
        self.assertEqual(state['anonsurf']['dns'], 'clearnet')

    @patch.object(network.platform, 'system', return_value='Linux')
    @patch.object(network, 'managed_interface', return_value=None)
    @patch.object(network, 'default_interface', return_value=None)
    @patch.object(network, 'find', side_effect=lambda p: '/usr/bin/anonsurf' if p=='anonsurf' else None)
    @patch.object(network, 'read_command', return_value=('',1,'Permission denied'))
    def test_status_failure_is_unknown_not_stopped(self, *mocks):
        state=network.status()
        self.assertEqual(state['anonsurf']['state'], 'unknown')
        self.assertIn('Permission denied',state['anonsurf']['error'])

    @patch.object(network.platform, 'system', return_value='Linux')
    @patch.object(network, 'find', return_value='/usr/bin/macchanger')
    def test_mac_change_requires_anonsurf_stopped(self, *mocks):
        state={'anonsurf':{'state':'active'},'macchanger':{'reason':None,'managed':False,'interface':'eth0'}}
        with self.assertRaisesRegex(ValueError, 'Stop AnonSurf'):
            network.command('macchanger','start',state)

    @patch.object(network.platform, 'system', return_value='Linux')
    @patch.object(network, 'find', return_value='/usr/bin/macchanger')
    def test_mac_action_uses_existing_restorable_helper(self, *mocks):
        state={'anonsurf':{'state':'inactive'},'macchanger':{'reason':None,'managed':False,'interface':'eth0'}}
        cmd=network.command('macchanger','start',state)
        self.assertEqual(cmd[-2:],['mac-start','eth0'])
        with self.assertRaisesRegex(ValueError, 'No MAC session'):
            network.command('macchanger','stop',state)

    @patch.object(network.platform, 'system', return_value='Windows')
    def test_windows_control_explains_support(self, *mocks):
        with self.assertRaisesRegex(ValueError, 'Linux'):
            network.command('anonsurf','start',{})


class MacHelperTests(unittest.TestCase):
    def test_mac_only_does_not_start_anonsurf(self):
        spec=importlib.util.spec_from_file_location('anon_helper',Path(__file__).parents[2]/'anon-control.py')
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory() as temp:
            helper.STATE=Path(temp)/'state.json'
            def command(*args, **kwargs):
                if args[:3]==('nmcli','-g','GENERAL.TYPE'): return 'wifi'
                if args[:3]==('nmcli','-g','GENERAL.CON-UUID'): return 'test-uuid'
                return ''
            with patch.object(helper,'run',side_effect=command) as run, patch.object(helper.subprocess,'run') as process, patch.object(helper.Path,'read_text',side_effect=['00:11:22:33:44:55','02:11:22:33:44:55','02:11:22:33:44:55']), patch.object(helper,'publish') as publish:
                process.return_value.returncode=3
                helper.start('wlan0',with_anonsurf=False)
                self.assertFalse(any(call.args[:2]==('anonsurf','start') for call in run.call_args_list))
                publish.assert_called_once()
                self.assertTrue(helper.STATE.exists())


if __name__ == '__main__': unittest.main()
