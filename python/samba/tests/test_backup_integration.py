# Integration tests for backup metadata functionality
#
# This test file validates the integration of backup metadata collection
# into the existing backup infrastructure.

import unittest
import tempfile
import os
import sys
import logging
from unittest.mock import Mock, patch, MagicMock

# Import the backup module to test integration
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from samba.netcmd.domain.backup import (
    cmd_domain_backup_list_objects,
    cmd_domain_backup_search_object,
    cmd_domain_backup_export_ldif,
    cmd_domain_backup_compare
)


class BackupIntegrationTestBase(unittest.TestCase):
    """Base class for backup integration tests."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.backup_file = os.path.join(self.temp_dir, "test_backup.tar.bz2")

        # Create a mock backup file with metadata
        self.create_mock_backup()

        # Suppress logging during tests
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        """Clean up test environment."""
        logging.disable(logging.NOTSET)
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)

    def create_mock_backup(self):
        """Create a mock backup file for testing."""
        import tarfile
        import json

        # Create mock metadata
        mock_metadata = {
            "version": "1.0",
            "backup_date": "2025-01-14T00:30:00",
            "backup_type": "test",
            "domain_info": {
                "domain_dn": "DC=test,DC=example,DC=com",
                "domain_sid": "S-1-5-21-test"
            },
            "objects": {
                "CN=testuser,CN=Users,DC=test,DC=example,DC=com": {
                    "dn": "CN=testuser,CN=Users,DC=test,DC=example,DC=com",
                    "objectClass": ["top", "person", "user"],
                    "objectGUID": "12345678901234567890123456789012",
                    "objectSid": "S-1-5-21-test-1001",
                    "attributes": {
                        "sAMAccountName": "testuser",
                        "cn": "testuser"
                    }
                },
                "CN=testgroup,CN=Users,DC=test,DC=example,DC=com": {
                    "dn": "CN=testgroup,CN=Users,DC=test,DC=example,DC=com",
                    "objectClass": ["top", "group"],
                    "objectGUID": "abcdefghijklmnopqrstuvwxyz123456",
                    "objectSid": "S-1-5-21-test-2001",
                    "attributes": {
                        "sAMAccountName": "testgroup",
                        "cn": "testgroup"
                    }
                }
            }
        }

        # Create temporary metadata file
        metadata_file = os.path.join(self.temp_dir, "backup_metadata.json")
        with open(metadata_file, 'w') as f:
            json.dump(mock_metadata, f, indent=2)

        # Create mock backup tar file
        with tarfile.open(self.backup_file, 'w:bz2') as tar:
            tar.add(metadata_file, arcname="backup_metadata.json")

        # Remove temporary metadata file
        os.unlink(metadata_file)


class TestBackupListObjects(BackupIntegrationTestBase):
    """Test the list-objects command integration."""

    def test_list_objects_command_exists(self):
        """Test that the list-objects command can be instantiated."""
        cmd = cmd_domain_backup_list_objects()
        self.assertIsNotNone(cmd)
        self.assertTrue(hasattr(cmd, 'run'))

    @patch('samba.netcmd.domain.backup.LdbAnalyzer')
    def test_list_objects_functionality(self, mock_analyzer_class):
        """Test list-objects command functionality."""
        # Mock LdbAnalyzer behavior
        mock_analyzer = Mock()
        mock_analyzer.list_objects.return_value = [
            {
                'dn': 'CN=testuser,CN=Users,DC=test,DC=example,DC=com',
                'objectClass': ['user'],
                'objectGUID': '12345678901234567890123456789012'
            }
        ]
        mock_analyzer_class.return_value = mock_analyzer

        # Create command instance
        cmd = cmd_domain_backup_list_objects()
        cmd.outf = Mock()

        # Run command
        cmd.run(backup_file=self.backup_file)

        # Verify interactions
        mock_analyzer_class.assert_called_once_with(self.backup_file, extract=False)
        mock_analyzer.list_objects.assert_called_once_with(object_class=None)
        mock_analyzer.cleanup.assert_called_once()

        # Verify output
        self.assertTrue(cmd.outf.write.called)

    def test_list_objects_error_handling(self):
        """Test error handling in list-objects command."""
        cmd = cmd_domain_backup_list_objects()

        # Test with non-existent file
        with self.assertRaises(Exception):
            cmd.run(backup_file="/nonexistent/file.tar.bz2")


class TestBackupSearchObject(BackupIntegrationTestBase):
    """Test the search-object command integration."""

    @patch('samba.netcmd.domain.backup.LdbAnalyzer')
    def test_search_by_dn(self, mock_analyzer_class):
        """Test search-object command with DN search."""
        # Mock LdbAnalyzer behavior
        mock_analyzer = Mock()
        mock_analyzer.search_by_dn.return_value = {
            'dn': 'CN=testuser,CN=Users,DC=test,DC=example,DC=com',
            'objectClass': ['user'],
            'objectGUID': '12345678901234567890123456789012'
        }
        mock_analyzer_class.return_value = mock_analyzer

        # Create command instance
        cmd = cmd_domain_backup_search_object()
        cmd.outf = Mock()

        # Run command
        test_dn = "CN=testuser,CN=Users,DC=test,DC=example,DC=com"
        cmd.run(backup_file=self.backup_file, dn=test_dn)

        # Verify interactions
        mock_analyzer.search_by_dn.assert_called_once_with(test_dn, scope="base")
        mock_analyzer.cleanup.assert_called_once()

    @patch('samba.netcmd.domain.backup.LdbAnalyzer')
    def test_search_by_guid(self, mock_analyzer_class):
        """Test search-object command with GUID search."""
        mock_analyzer = Mock()
        mock_analyzer.search_by_guid.return_value = {
            'dn': 'CN=testuser,CN=Users,DC=test,DC=example,DC=com',
            'objectGUID': '12345678901234567890123456789012'
        }
        mock_analyzer_class.return_value = mock_analyzer

        cmd = cmd_domain_backup_search_object()
        cmd.outf = Mock()

        test_guid = "12345678-9012-3456-7890-123456789012"
        cmd.run(backup_file=self.backup_file, guid=test_guid)

        mock_analyzer.search_by_guid.assert_called_once_with(test_guid)

    def test_search_object_parameter_validation(self):
        """Test parameter validation in search-object command."""
        cmd = cmd_domain_backup_search_object()

        # Test with no search parameters
        with self.assertRaises(Exception):
            cmd.run(backup_file=self.backup_file)

        # Test with multiple search parameters
        with self.assertRaises(Exception):
            cmd.run(backup_file=self.backup_file, dn="test", guid="test")


class TestBackupExportLdif(BackupIntegrationTestBase):
    """Test the export-ldif command integration."""

    @patch('samba.netcmd.domain.backup.LdbAnalyzer')
    def test_export_ldif_functionality(self, mock_analyzer_class):
        """Test export-ldif command functionality."""
        mock_analyzer = Mock()
        mock_analyzer.export_to_ldif.return_value = """dn: CN=testuser,CN=Users,DC=test,DC=example,DC=com
objectClass: top
objectClass: person
objectClass: user
cn: testuser"""
        mock_analyzer_class.return_value = mock_analyzer

        cmd = cmd_domain_backup_export_ldif()
        cmd.outf = Mock()

        test_dn = "CN=testuser,CN=Users,DC=test,DC=example,DC=com"
        cmd.run(backup_file=self.backup_file, dn=test_dn)

        mock_analyzer.export_to_ldif.assert_called_once_with(test_dn)
        self.assertTrue(cmd.outf.write.called)

    @patch('samba.netcmd.domain.backup.LdbAnalyzer')
    def test_export_ldif_to_file(self, mock_analyzer_class):
        """Test export-ldif command with file output."""
        mock_analyzer = Mock()
        mock_analyzer.export_to_ldif.return_value = "test ldif data"
        mock_analyzer_class.return_value = mock_analyzer

        cmd = cmd_domain_backup_export_ldif()
        cmd.outf = Mock()

        output_file = os.path.join(self.temp_dir, "test_output.ldif")
        test_dn = "CN=testuser,CN=Users,DC=test,DC=example,DC=com"

        cmd.run(backup_file=self.backup_file, dn=test_dn, output=output_file)

        # Verify file was created
        self.assertTrue(os.path.exists(output_file))

        # Verify file contents
        with open(output_file, 'r') as f:
            contents = f.read()
        self.assertEqual(contents, "test ldif data")


class TestBackupCompare(BackupIntegrationTestBase):
    """Test the compare command integration."""

    def setUp(self):
        """Set up test environment with two backup files."""
        super().setUp()
        self.backup_file2 = os.path.join(self.temp_dir, "test_backup2.tar.bz2")
        # Create second backup file (copy of first for simplicity)
        import shutil
        shutil.copy(self.backup_file, self.backup_file2)

    @patch('samba.netcmd.domain.backup.LdbAnalyzer')
    def test_compare_functionality(self, mock_analyzer_class):
        """Test compare command functionality."""
        # Create two mock analyzers
        mock_analyzer1 = Mock()
        mock_analyzer2 = Mock()

        mock_analyzer1.compare_with.return_value = {
            'added': ['CN=newuser,CN=Users,DC=test,DC=example,DC=com'],
            'deleted': ['CN=olduser,CN=Users,DC=test,DC=example,DC=com'],
            'modified': {
                'CN=moduser,CN=Users,DC=test,DC=example,DC=com': {
                    'old': '2025-01-01T00:00:00',
                    'new': '2025-01-14T00:00:00'
                }
            }
        }

        # Mock the class to return different instances
        mock_analyzer_class.side_effect = [mock_analyzer1, mock_analyzer2]

        cmd = cmd_domain_backup_compare()
        cmd.outf = Mock()

        cmd.run(backup1=self.backup_file, backup2=self.backup_file2)

        # Verify both analyzers were created
        self.assertEqual(mock_analyzer_class.call_count, 2)
        mock_analyzer1.compare_with.assert_called_once_with(mock_analyzer2)

        # Verify cleanup was called
        mock_analyzer1.cleanup.assert_called_once()
        mock_analyzer2.cleanup.assert_called_once()

        # Verify output contains comparison results
        output_calls = [call[0][0] for call in cmd.outf.write.call_args_list]
        output_text = ''.join(output_calls)

        self.assertIn('Added objects', output_text)
        self.assertIn('Deleted objects', output_text)
        self.assertIn('Modified objects', output_text)

    @patch('samba.netcmd.domain.backup.LdbAnalyzer')
    def test_compare_no_differences(self, mock_analyzer_class):
        """Test compare command with no differences."""
        mock_analyzer1 = Mock()
        mock_analyzer2 = Mock()

        mock_analyzer1.compare_with.return_value = {
            'added': [],
            'deleted': [],
            'modified': {}
        }

        mock_analyzer_class.side_effect = [mock_analyzer1, mock_analyzer2]

        cmd = cmd_domain_backup_compare()
        cmd.outf = Mock()

        cmd.run(backup1=self.backup_file, backup2=self.backup_file2)

        # Verify "no differences" message
        output_calls = [call[0][0] for call in cmd.outf.write.call_args_list]
        output_text = ''.join(output_calls)
        self.assertIn('No differences found', output_text)


class TestIntegrationErrorHandling(BackupIntegrationTestBase):
    """Test error handling in integration scenarios."""

    def test_missing_backup_file(self):
        """Test handling of missing backup files."""
        commands = [
            cmd_domain_backup_list_objects(),
            cmd_domain_backup_search_object(),
            cmd_domain_backup_export_ldif(),
            cmd_domain_backup_compare()
        ]

        for cmd in commands:
            with self.subTest(command=cmd.__class__.__name__):
                with self.assertRaises(Exception):
                    if hasattr(cmd, 'run'):
                        if 'compare' in cmd.__class__.__name__.lower():
                            cmd.run(backup1="/nonexistent1.tar.bz2", backup2="/nonexistent2.tar.bz2")
                        else:
                            cmd.run(backup_file="/nonexistent.tar.bz2")

    @patch('samba.netcmd.domain.backup.LdbAnalyzer')
    def test_analyzer_exception_handling(self, mock_analyzer_class):
        """Test handling of LdbAnalyzer exceptions."""
        # Mock analyzer to raise exception
        mock_analyzer_class.side_effect = Exception("Test analyzer error")

        cmd = cmd_domain_backup_list_objects()

        with self.assertRaises(Exception):
            cmd.run(backup_file=self.backup_file)


if __name__ == '__main__':
    unittest.main()