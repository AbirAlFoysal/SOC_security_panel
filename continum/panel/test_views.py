import json
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase


class DjangoBridgeTests(SimpleTestCase):
    def test_existing_homepage_is_served_with_local_tailwind_styles(self):
        response = self.client.get("/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/static/panel/tailwind.css")
        self.assertContains(response, "min-h-screen bg-slate-950 text-slate-100")
        self.assertContains(response, "/continum-mode.js")
        self.assertContains(response, 'id="network-refresh"')
        self.assertContains(response, 'id="tool-refresh"')

    def test_continum_mode_script_marks_continum_pages(self):
        response = self.client.get("/continum-mode.js", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "window.CONTINUM_MODE = true")

    def test_project_api_is_served_through_django(self):
        response = self.client.get("/api/projects", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(response.status_code, 200)
        self.assertIn("projects", response.json())
        self.assertIn("statuses", response.json())

    @patch("panel.views.get_legacy")
    def test_batch_scan_rejects_targets_outside_project_scope(self, get_legacy):
        get_legacy.return_value = SimpleNamespace(
            TOKEN="test-token",
            PROJECTS=SimpleNamespace(get=lambda _ident: {"host": "example.test", "ip": ""}),
        )
        response = self.client.post(
            "/api/projects/project-id/nuclei_batch",
            data=json.dumps({"targets": "https://outside.test"}),
            content_type="application/json",
            HTTP_HOST="127.0.0.1:8000",
            HTTP_X_APP_TOKEN="test-token",
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("exactly match", response.json()["error"])
