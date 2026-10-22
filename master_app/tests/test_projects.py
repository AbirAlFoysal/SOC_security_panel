import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).parents[1]))
from project_store import ProjectStore, DuplicateProjectError


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'projects'
        self.store = ProjectStore(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_named_notes_reopen_rename_delete_and_isolation(self):
        project = self.store.save({'host': 'notes.test'})
        other = self.store.save({'host': 'other.test'})
        ident = project['id']
        first = self.store.notes(ident, {'title': 'First', 'notes': 'Saved content'})
        first_id = first['selected_note_id']
        second = self.store.notes(ident, {'title': 'Second', 'notes': 'Other content'})
        second_id = second['selected_note_id']
        reopened = ProjectStore(self.root).get(ident)
        self.assertEqual(len(reopened['saved_notes']), 2)
        self.assertEqual(reopened['saved_notes'][1]['content'], 'Saved content')
        renamed = self.store.notes(ident, {'action': 'rename', 'id': first_id, 'title': 'Renamed'})
        self.assertEqual(renamed['saved_notes'][1]['title'], 'Renamed')
        self.assertEqual(renamed['saved_notes'][1]['content'], 'Saved content')
        with self.assertRaises(FileNotFoundError):
            self.store.notes(other['id'], {'action': 'delete', 'id': first_id})
        edited = self.store.notes(ident, {'id': first_id, 'title': 'Renamed', 'notes': 'Edited'})
        self.assertEqual(len(edited['saved_notes']), 2)
        deleted = self.store.notes(ident, {'action': 'delete', 'id': second_id})
        self.assertEqual([n['id'] for n in deleted['saved_notes']], [first_id])
        self.assertEqual(deleted['saved_notes'][0]['content'], 'Edited')
        self.store.notes(ident, {'action': 'delete', 'id': first_id})
        self.assertEqual(ProjectStore(self.root).get(ident)['saved_notes'], [])

    def test_legacy_notes_migrate_once_without_losing_text(self):
        project = self.store.save({'host': 'legacy.test'})
        directory = self.root / project['id']
        (directory / 'notes.json').unlink()
        (directory / 'notes.md').write_text('Original notes\n', encoding='utf-8')
        migrated = self.store.get(project['id'])
        self.assertEqual(migrated['saved_notes'][0]['title'], 'Project notes')
        self.assertEqual(migrated['saved_notes'][0]['content'], 'Original notes\n')
        self.assertEqual(self.store.get(project['id'])['saved_notes'], migrated['saved_notes'])

    def test_document_entries_text_files_edit_rename_delete(self):
        ident = self.store.save({'host': 'docs.test'})['id']
        files = [{'name': name, 'content': base64.b64encode(content).decode()} for name, content in [('one.txt', b'one'), ('two.txt', b'two')]]
        saved = self.store.document(ident, {'action': 'save', 'title': 'Findings', 'text': 'Written context', 'files': files})
        entry_id = saved['selected_document_id']
        reopened = ProjectStore(self.root).get(ident)
        entry = reopened['document_entries'][0]
        self.assertEqual(entry['text'], 'Written context')
        self.assertEqual(len(entry['attachments']), 2)
        self.assertEqual(self.store.download(ident, entry['attachments'][0]), b'one')
        edited = self.store.document(ident, {'action': 'save', 'id': entry_id, 'title': 'Findings', 'text': 'Edited'})
        self.assertEqual(len(edited['document_entries'][0]['attachments']), 2)
        renamed = self.store.document(ident, {'action': 'rename', 'id': entry_id, 'title': 'Renamed'})
        self.assertEqual(renamed['document_entries'][0]['text'], 'Edited')
        self.assertEqual(renamed['document_entries'][0]['title'], 'Renamed')
        other = self.store.save({'host': 'other-docs.test'})['id']
        with self.assertRaises(FileNotFoundError):
            self.store.document(other, {'action': 'delete', 'id': entry_id})
        self.store.document(ident, {'action': 'save', 'title': 'Keep', 'text': 'Independent'})
        deleted = self.store.document(ident, {'action': 'delete', 'id': entry_id})
        self.assertEqual([d['title'] for d in deleted['document_entries']], ['Keep'])
        for attachment_id in entry['attachments']:
            self.assertFalse((self.root / ident / 'docs' / attachment_id).exists())

    def test_legacy_document_migration_and_invalid_upload(self):
        ident = self.store.save({'host': 'old-docs.test'})['id']
        saved = self.store.document(ident, {'name': 'old.txt', 'content': base64.b64encode(b'original').decode()})
        path = self.root / ident / 'project.json'
        metadata = json.loads(path.read_text())
        metadata.pop('document_entries')
        path.write_text(json.dumps(metadata))
        migrated = ProjectStore(self.root).get(ident)
        self.assertEqual(migrated['document_entries'][0]['title'], 'old.txt')
        self.assertEqual(self.store.download(ident, migrated['document_entries'][0]['attachments'][0]), b'original')
        with self.assertRaises(ValueError):
            self.store.document(ident, {'action': 'save', 'files': [{'name': '../escape', 'content': ''}]})
        with self.assertRaises(ValueError):
            self.store.document(ident, {'action': 'save', 'files': [{'name': 'bad', 'content': '@@@'}]})
        self.assertEqual(len(self.store.get(ident)['document_entries']), 1)

    def test_project_persists_in_its_own_directory(self):
        p = self.store.save({'host': 'example.test', 'others': 'Scope'})
        self.assertEqual(p['name'], 'example.test')
        self.assertTrue((self.root / p['id'] / 'project.json').is_file())
        reopened = ProjectStore(self.root)
        self.assertEqual(reopened.list()[0]['id'], p['id'])
        self.assertEqual(reopened.get(p['id'])['others'], 'Scope')

    def test_project_defaults_and_explicit_name(self):
        cases = [
            ({'host': 'example.test', 'ip': '127.0.0.1'}, 'example.test'),
            ({'ip': '127.0.0.1'}, '127.0.0.1'),
            ({'name': ' My project ', 'host': 'example.test'}, 'My project'),
            ({'name': '   ', 'host': 'example.test'}, 'example.test'),
        ]
        for data, expected in cases:
            with self.subTest(data=data):
                project = self.store.save(data)
                self.assertEqual(project['name'], expected)
                self.assertEqual(project['status'], 'test')

    def test_default_status_available_with_existing_custom_statuses(self):
        self.store._write(self.root / 'statuses.json', ['Planned', 'Review'])
        self.assertIn('test', self.store.statuses())
        self.assertIn('Review', self.store.statuses())
        self.assertEqual(self.store.save({'host': 'example.test'})['status'], 'test')

    def test_duplicate_target_requires_explicit_choice(self):
        original = self.store.create({'host': 'Example.TEST.', 'ip': '127.0.0.1'})
        self.store.notes(original['id'], {'notes': 'Original notes'})
        for data in ({'host': 'https://example.test/path'}, {'ip': '127.0.0.1'}, {'host': '127.0.0.1'}):
            with self.subTest(data=data):
                with self.assertRaises(DuplicateProjectError) as conflict:
                    self.store.create(data)
                self.assertEqual(conflict.exception.projects[0]['id'], original['id'])
        self.assertEqual(len(self.store.list()), 1)
        self.assertEqual(self.store.get(original['id'])['notes'], 'Original notes')

    def test_copy_creates_independent_saved_project(self):
        original = self.store.create({'ip': '127.0.0.1'})
        self.store.notes(original['id'], {'notes': 'Keep original'})
        copied = self.store.create({'ip': '127.0.0.1', 'duplicate': 'copy'})
        self.assertNotEqual(original['id'], copied['id'])
        self.assertEqual(copied['name'], '127.0.0.1')
        self.assertEqual(copied['notes'], '')
        self.assertEqual(len(ProjectStore(self.root).list()), 2)
        self.assertEqual(self.store.get(original['id'])['notes'], 'Keep original')

    def test_equivalent_ipv6_matches(self):
        self.store.create({'ip': '2001:db8::1'})
        with self.assertRaises(DuplicateProjectError):
            self.store.create({'ip': '2001:0db8:0:0:0:0:0:1'})

    def test_requires_host_or_valid_ip(self):
        for payload in ({}, {'ip': 'not-an-ip'}):
            with self.assertRaises(ValueError):
                self.store.save(payload)
        self.store.save({'ip': '2001:db8::1'})

    def test_custom_status_and_edits_preserve_notes_and_docs(self):
        self.store.add_status({'name': 'Needs review'})
        p = self.store.save({'ip': '127.0.0.1', 'status': 'Needs review'})
        self.store.notes(p['id'], {'notes': 'Persisted\nnotes'})
        p = self.store.document(p['id'], {'name': 'report.txt', 'content': base64.b64encode(b'findings').decode()})
        docid = p['documents'][0]['id']
        self.store.save({'host': 'example.test', 'status': 'Completed'}, p['id'])
        p = self.store.get(p['id'])
        self.assertEqual(p['notes'], 'Persisted\nnotes')
        self.assertEqual(self.store.download(p['id'], docid), b'findings')
        self.assertEqual(p['status'], 'Completed')
        self.assertIn('Needs review', ProjectStore(self.root).statuses())

    def test_rejects_traversal_and_unregistered_status(self):
        with self.assertRaises(ValueError):
            self.store.get('../../elsewhere')
        with self.assertRaises(ValueError):
            self.store.save({'host': 'example.test', 'status': 'unknown'})
        p = self.store.save({'host': 'example.test'})
        with self.assertRaises(ValueError):
            self.store.document(p['id'], {'name': '../bad', 'content': ''})

    def test_history_is_empty_and_project_specific(self):
        a = self.store.save({'host': 'a.test'})
        b = self.store.save({'host': 'b.test'})
        self.store.notes(a['id'], {'notes': 'Only project A'})
        self.assertEqual(self.store.get(b['id'])['notes'], '')
        self.assertEqual(a['tool_history'], {})


if __name__ == '__main__':
    unittest.main()

class ProjectStatusTests(unittest.TestCase):
    def test_status_update_preserves_project_content(self):
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects')
            project=store.create({'name':'Assessment','host':'example.test','others':'Keep details'})
            store.notes(project['id'],{'notes':'Keep notes'})
            updated=store.set_status(project['id'],{'status':'In progress'})
            self.assertEqual(updated['status'],'In progress')
            self.assertEqual(updated['name'],'Assessment')
            self.assertEqual(updated['others'],'Keep details')
            self.assertEqual(updated['notes'],'Keep notes')
            self.assertEqual(ProjectStore(store.root).get(project['id'])['status'],'In progress')
            with self.assertRaises(ValueError):store.set_status(project['id'],{'status':'Unknown'})
