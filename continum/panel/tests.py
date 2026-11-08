from types import SimpleNamespace

from django.test import SimpleTestCase

from panel.views import _host, _scope_error, _within_project_scope


class ProjectScopeTests(SimpleTestCase):
    def setUp(self):
        self.project = {"host": "Example.test", "ip": "192.0.2.10"}

    def test_exact_host_accepts_scheme_and_path(self):
        self.assertTrue(_within_project_scope(
            self.project,
            ["https://example.test/health?check=1"],
        ))

    def test_exact_ip_and_host_are_allowed(self):
        self.assertTrue(_within_project_scope(
            self.project,
            ["example.test\nhttp://192.0.2.10:8080"],
        ))

    def test_subdomains_and_other_hosts_are_rejected(self):
        self.assertFalse(_within_project_scope(
            self.project,
            ["https://sub.example.test"],
        ))
        self.assertFalse(_within_project_scope(
            self.project,
            ["https://other.test"],
        ))

    def test_empty_and_malformed_targets_are_rejected(self):
        self.assertFalse(_within_project_scope(self.project, [""]))
        self.assertIsNone(_host("https://user:pass@example.test"))
        self.assertIsNone(_host("not a host"))

    def test_nmap_guard_rejects_targets_outside_the_project(self):
        def parse_nmap(command):
            tokens = command.split()
            return tokens, tokens[2:], False

        legacy = SimpleNamespace(
            PROJECTS=SimpleNamespace(get=lambda _ident: self.project),
            NMAP=SimpleNamespace(validate_command=parse_nmap),
            WEB_SCANS={},
            CLI_CONFIG={},
        )
        self.assertIsNone(_scope_error(
            legacy,
            "/api/projects/project-id/nmap",
            {"command": "nmap -sT example.test"},
        ))
        self.assertIsNotNone(_scope_error(
            legacy,
            "/api/projects/project-id/nmap",
            {"command": "nmap -sT other.test"},
        ))
