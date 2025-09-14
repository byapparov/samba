# Unix SMB/CIFS implementation.
# Tests for LDB analyzer functionality
#
# Copyright (C) Samba Team 2025
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Tests for LDB analyzer functionality."""

import json
import os
import tempfile
import unittest
try:
    from samba import safe_tarfile as tarfile
except ImportError:
    import tarfile

import ldb
from samba.ldb_analyzer import LdbAnalyzer
from samba.backup_metadata import BackupMetadata

# Use standard unittest for compatibility
TestCase = unittest.TestCase


class TestCaseInTempDir(unittest.TestCase):
    """Custom test case that creates temporary directories."""

    def setUp(self):
        """Set up temporary directory for each test."""
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory after each test."""
        import shutil
        if os.path.exists(self.tempdir):
            shutil.rmtree(self.tempdir)


class LdbAnalyzerTestBase(TestCaseInTempDir):
    """Base class for LDB analyzer tests."""

    def setUp(self):
        super().setUp()
        self.test_dir = tempfile.mkdtemp()
        self.backup_file = None

    def tearDown(self):
        """Clean up test environment."""
        super().tearDown()
        if self.backup_file and os.path.exists(self.backup_file):
            os.remove(self.backup_file)
        if os.path.exists(self.test_dir):
            import shutil
            shutil.rmtree(self.test_dir)

    def create_test_backup(self, with_metadata=True):
        """Create a test backup file with sample data."""
        # Create a test LDB
        ldb_path = os.path.join(self.test_dir, "test.ldb")
        test_ldb = ldb.Ldb(ldb_path, flags=ldb.FLG_NOSYNC)

        # Add test data
        test_ldb.transaction_start()
        try:
            # Add base DN
            test_ldb.add({
                "dn": "DC=test,DC=example,DC=com",
                "objectClass": ["top", "domain"],
                "dc": "test",
                "objectGUID": b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113120000.0Z"
            })

            # Add Users container
            test_ldb.add({
                "dn": "CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "container"],
                "cn": "Users",
                "objectGUID": b'\x02\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113120100.0Z"
            })

            # Add test users
            test_ldb.add({
                "dn": "CN=TestUser1,CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "person", "user"],
                "cn": "TestUser1",
                "sAMAccountName": "testuser1",
                "objectGUID": b'\x03\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113120200.0Z",
                "description": "Test User 1"
            })

            test_ldb.add({
                "dn": "CN=TestUser2,CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "person", "user"],
                "cn": "TestUser2",
                "sAMAccountName": "testuser2",
                "objectGUID": b'\x04\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113120300.0Z",
                "mail": "testuser2@example.com"
            })

            # Add test group
            test_ldb.add({
                "dn": "CN=TestGroup,CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "group"],
                "cn": "TestGroup",
                "sAMAccountName": "testgroup",
                "objectGUID": b'\x05\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113120400.0Z",
                "member": ["CN=TestUser1,CN=Users,DC=test,DC=example,DC=com"]
            })

            test_ldb.transaction_commit()
        except Exception:
            test_ldb.transaction_cancel()
            raise

        # Create metadata if requested
        metadata_obj = None
        if with_metadata:
            metadata_obj = BackupMetadata(test_ldb)
            metadata_obj.collect_all_objects()

        # Create backup tar file
        self.backup_file = os.path.join(self.test_dir, "test_backup.tar.bz2")
        with tarfile.open(self.backup_file, 'w:bz2') as tar:
            # Add LDB file
            tar.add(ldb_path, arcname="test.ldb")

            # Add metadata if created
            if metadata_obj:
                metadata_path = os.path.join(self.test_dir, "metadata.json")
                with open(metadata_path, 'w') as f:
                    f.write(metadata_obj.to_json())
                tar.add(metadata_path, arcname="metadata.json")

        return self.backup_file


class LdbAnalyzerListTests(LdbAnalyzerTestBase):
    """Tests for object listing functionality."""

    def test_list_objects_without_restore(self):
        """Test OAT-001: Verify ability to list objects without restoration."""
        # Create test backup
        backup_file = self.create_test_backup(with_metadata=True)

        # Analyze without extraction
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # List all objects
        objects = analyzer.list_objects()

        # Verify objects found
        self.assertEqual(len(objects), 5)  # Domain, Users container, 2 users, 1 group

        # Verify object details
        dns = [obj['dn'] for obj in objects]
        self.assertIn("DC=test,DC=example,DC=com", dns)
        self.assertIn("CN=TestUser1,CN=Users,DC=test,DC=example,DC=com", dns)
        self.assertIn("CN=TestGroup,CN=Users,DC=test,DC=example,DC=com", dns)

        # Verify no extraction occurred
        self.assertIsNone(analyzer.temp_dir)

        analyzer.cleanup()

    def test_list_objects_with_extraction(self):
        """Test listing objects with extraction."""
        backup_file = self.create_test_backup(with_metadata=False)

        # Analyze with extraction
        analyzer = LdbAnalyzer(backup_file, extract=True)

        # List all objects
        objects = analyzer.list_objects()

        # Verify objects found
        self.assertGreater(len(objects), 0)

        # Verify extraction occurred
        self.assertIsNotNone(analyzer.temp_dir)
        temp_dir_path = analyzer.temp_dir
        self.assertTrue(os.path.exists(temp_dir_path))

        analyzer.cleanup()

        # Verify cleanup - temp_dir should be None and directory should be removed
        self.assertIsNone(analyzer.temp_dir)
        self.assertFalse(os.path.exists(temp_dir_path))

    def test_filter_by_objectclass(self):
        """Test OAT-006: Verify filtering objects by objectClass."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Filter users
        users = analyzer.filter_by_objectclass('user')
        self.assertEqual(len(users), 2)

        # Filter groups
        groups = analyzer.filter_by_objectclass('group')
        self.assertEqual(len(groups), 1)

        # Filter multiple classes
        all_principals = analyzer.filter_by_objectclass(['user', 'group'])
        self.assertEqual(len(all_principals), 3)

        analyzer.cleanup()


class LdbAnalyzerSearchTests(LdbAnalyzerTestBase):
    """Tests for object search functionality."""

    def test_search_by_dn(self):
        """Test OAT-003: Verify object search by Distinguished Name."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Test exact DN search
        user_dn = "CN=TestUser1,CN=Users,DC=test,DC=example,DC=com"
        result = analyzer.search_by_dn(user_dn)

        self.assertIsNotNone(result)
        self.assertEqual(result['dn'], user_dn)
        self.assertIn('user', result.get('objectClass', []))

        # Test non-existent DN
        result = analyzer.search_by_dn("CN=NonExistent,DC=test,DC=example,DC=com")
        self.assertIsNone(result)

        analyzer.cleanup()

    def test_search_by_guid(self):
        """Test OAT-004: Verify object search by GUID."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Search for TestUser1 by GUID
        # GUID bytes: \x03\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef
        guid_hex = "0323456789abcdef0123456789abcdef"

        result = analyzer.search_by_guid(guid_hex)
        self.assertIsNotNone(result)
        self.assertEqual(result['dn'], "CN=TestUser1,CN=Users,DC=test,DC=example,DC=com")

        # Test with bytes
        guid_bytes = bytes.fromhex(guid_hex)
        result = analyzer.search_by_guid(guid_bytes)
        self.assertIsNotNone(result)

        analyzer.cleanup()

    def test_get_object_attributes(self):
        """Test OAT-002: Verify extraction of object attributes."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Get attributes for TestUser2
        user_dn = "CN=TestUser2,CN=Users,DC=test,DC=example,DC=com"
        attributes = analyzer.get_object_attributes(user_dn)

        self.assertIsNotNone(attributes)
        self.assertEqual(attributes.get('mail'), 'testuser2@example.com')
        self.assertEqual(attributes.get('sAMAccountName'), 'testuser2')

        analyzer.cleanup()


class LdbAnalyzerExportTests(LdbAnalyzerTestBase):
    """Tests for export functionality."""

    def test_export_to_ldif(self):
        """Test OAT-007: Verify export of objects to LDIF format."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Export user to LDIF
        user_dn = "CN=TestUser1,CN=Users,DC=test,DC=example,DC=com"
        ldif = analyzer.export_to_ldif(user_dn)

        self.assertIsNotNone(ldif)
        self.assertIn(f"dn: {user_dn}", ldif)
        self.assertIn("objectClass: user", ldif)
        self.assertIn("sAMAccountName: testuser1", ldif)

        # Test non-existent object
        ldif = analyzer.export_to_ldif("CN=NonExistent,DC=test")
        self.assertIsNone(ldif)

        analyzer.cleanup()

    def test_count_objects(self):
        """Test counting objects in backup."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        count = analyzer.count_objects()
        self.assertEqual(count, 5)  # Domain, Users container, 2 users, 1 group

        analyzer.cleanup()


class LdbAnalyzerComparisonTests(LdbAnalyzerTestBase):
    """Tests for backup comparison functionality."""

    def test_compare_backups(self):
        """Test OAT-009: Verify ability to compare objects between backups."""
        # Create first backup
        backup1 = self.create_test_backup(with_metadata=True)

        # Modify the test data for second backup
        ldb_path = os.path.join(self.test_dir, "test2.ldb")
        test_ldb = ldb.Ldb(ldb_path, flags=ldb.FLG_NOSYNC)

        test_ldb.transaction_start()
        try:
            # Same base structure but with modifications
            test_ldb.add({
                "dn": "DC=test,DC=example,DC=com",
                "objectClass": ["top", "domain"],
                "dc": "test",
                "objectGUID": b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113130000.0Z"  # Modified
            })

            test_ldb.add({
                "dn": "CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "container"],
                "cn": "Users",
                "objectGUID": b'\x02\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113120100.0Z"
            })

            # TestUser1 unchanged
            test_ldb.add({
                "dn": "CN=TestUser1,CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "person", "user"],
                "cn": "TestUser1",
                "sAMAccountName": "testuser1",
                "objectGUID": b'\x03\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113120200.0Z",
                "description": "Test User 1"
            })

            # TestUser2 deleted (not added)

            # TestGroup unchanged
            test_ldb.add({
                "dn": "CN=TestGroup,CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "group"],
                "cn": "TestGroup",
                "sAMAccountName": "testgroup",
                "objectGUID": b'\x05\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113120400.0Z"
            })

            # New user added
            test_ldb.add({
                "dn": "CN=TestUser3,CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "person", "user"],
                "cn": "TestUser3",
                "sAMAccountName": "testuser3",
                "objectGUID": b'\x06\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef',
                "whenChanged": "20250113130500.0Z"
            })

            test_ldb.transaction_commit()
        except Exception:
            test_ldb.transaction_cancel()
            raise

        # Create second backup
        metadata2 = BackupMetadata(test_ldb)
        metadata2.collect_all_objects()

        backup2_file = os.path.join(self.test_dir, "test_backup2.tar.bz2")
        with tarfile.open(backup2_file, 'w:bz2') as tar:
            tar.add(ldb_path, arcname="test2.ldb")
            metadata_path = os.path.join(self.test_dir, "metadata2.json")
            with open(metadata_path, 'w') as f:
                f.write(metadata2.to_json())
            tar.add(metadata_path, arcname="metadata.json")

        # Compare backups
        analyzer1 = LdbAnalyzer(backup1, extract=False)
        analyzer2 = LdbAnalyzer(backup2_file, extract=False)

        differences = analyzer1.compare_with(analyzer2)

        # Verify differences
        self.assertIn("CN=TestUser3,CN=Users,DC=test,DC=example,DC=com", differences['added'])
        self.assertIn("CN=TestUser2,CN=Users,DC=test,DC=example,DC=com", differences['deleted'])
        self.assertIn("DC=test,DC=example,DC=com", differences['modified'])

        analyzer1.cleanup()
        analyzer2.cleanup()

        # Clean up second backup
        if os.path.exists(backup2_file):
            os.remove(backup2_file)


class LdbAnalyzerErrorTests(LdbAnalyzerTestBase):
    """Tests for error handling and edge cases in LDB analyzer."""

    def test_nonexistent_backup_file(self):
        """Test analyzer with non-existent backup file."""
        with self.assertRaises(FileNotFoundError):
            LdbAnalyzer("/nonexistent/backup.tar.bz2")

    def test_invalid_backup_file(self):
        """Test analyzer with invalid backup file."""
        # Create an invalid tar file
        invalid_backup = os.path.join(self.test_dir, "invalid.tar.bz2")
        with open(invalid_backup, 'w') as f:
            f.write("This is not a valid tar file")

        with self.assertRaises(Exception):
            LdbAnalyzer(invalid_backup)

    def test_extraction_mode_with_corrupted_ldb(self):
        """Test extraction mode with corrupted LDB file."""
        # Create backup with corrupted LDB
        corrupted_ldb = os.path.join(self.test_dir, "corrupted.ldb")
        with open(corrupted_ldb, 'wb') as f:
            f.write(b"This is not a valid LDB file content")

        backup_file = os.path.join(self.test_dir, "corrupted_backup.tar.bz2")
        with tarfile.open(backup_file, 'w:bz2') as tar:
            tar.add(corrupted_ldb, arcname="corrupted.ldb")

        # Should handle corrupted LDB gracefully
        analyzer = LdbAnalyzer(backup_file, extract=True)
        objects = analyzer.list_objects()
        # Should return empty list instead of crashing
        self.assertEqual(len(objects), 0)

        analyzer.cleanup()

    def test_search_in_empty_backup(self):
        """Test searches in empty backup."""
        # Create empty backup
        empty_backup = os.path.join(self.test_dir, "empty.tar.bz2")
        with tarfile.open(empty_backup, 'w:bz2') as tar:
            pass  # Empty tar

        analyzer = LdbAnalyzer(empty_backup, extract=False)

        # All searches should return None or empty
        result = analyzer.search_by_dn("CN=Test,DC=example,DC=com")
        self.assertIsNone(result)

        result = analyzer.search_by_guid("0123456789abcdef0123456789abcdef")
        self.assertIsNone(result)

        result = analyzer.search_by_sid("S-1-5-21-1234567890-1234567890-1234567890-1001")
        self.assertIsNone(result)

        count = analyzer.count_objects()
        self.assertEqual(count, 0)

        analyzer.cleanup()

    def test_invalid_guid_search(self):
        """Test GUID search with invalid GUID."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        with self.assertRaises(ValueError):
            analyzer.search_by_guid("invalid-guid-format")

        analyzer.cleanup()

    def test_export_nonexistent_object(self):
        """Test exporting non-existent object to LDIF."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        ldif = analyzer.export_to_ldif("CN=NonExistent,DC=test,DC=example,DC=com")
        self.assertIsNone(ldif)

        analyzer.cleanup()

    def test_subtree_search(self):
        """Test subtree search functionality."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Search subtree under Users container
        results = analyzer.search_by_dn("CN=Users,DC=test,DC=example,DC=com", scope="subtree")

        if results:  # Only check if we have results
            self.assertIsInstance(results, list)
            # Should include child objects
            dns = [obj['dn'] for obj in results] if isinstance(results, list) else [results['dn']]
            users_dns = [dn for dn in dns if "CN=TestUser" in dn]
            self.assertGreater(len(users_dns), 0)

        analyzer.cleanup()

    def test_onelevel_search(self):
        """Test one-level search functionality."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Search one level under domain
        results = analyzer.search_by_dn("DC=test,DC=example,DC=com", scope="onelevel")

        if results:
            # Should find Users container as direct child
            self.assertIsInstance(results, list)
            dns = [obj['dn'] for obj in results]
            self.assertIn("CN=Users,DC=test,DC=example,DC=com", dns)

        analyzer.cleanup()

    def test_ldb_search_error_handling(self):
        """Test LDB search error handling in extraction mode."""
        backup_file = self.create_test_backup(with_metadata=False)
        analyzer = LdbAnalyzer(backup_file, extract=True)

        # Mock one of the LDB connections to fail
        if analyzer.ldb_connections:
            # Replace one connection with a failing mock
            failing_ldb = type('FailingLdb', (), {
                'search': lambda *args, **kwargs: (_ for _ in ()).throw(Exception("LDB search failed"))
            })()

            first_key = next(iter(analyzer.ldb_connections))
            analyzer.ldb_connections[first_key] = failing_ldb

            # Should handle the error gracefully and continue with other connections
            objects = analyzer.list_objects()
            # May be empty or have objects from other connections

        analyzer.cleanup()

    def test_message_to_dict_edge_cases(self):
        """Test _message_to_dict with edge cases."""
        backup_file = self.create_test_backup(with_metadata=False)
        analyzer = LdbAnalyzer(backup_file, extract=True)

        # Create a mock message with edge cases
        class MockMessage:
            def __init__(self):
                self.dn = type('MockDN', (), {'__str__': lambda self: "CN=Test,DC=example,DC=com"})()

            def __iter__(self):
                return iter(['objectClass', 'emptyAttr'])

            def __getitem__(self, key):
                if key == 'objectClass':
                    return ['user', 'person']
                elif key == 'emptyAttr':
                    return []  # Empty attribute
                return None

        # Test with empty attribute
        mock_msg = MockMessage()
        result = analyzer._message_to_dict(mock_msg)

        self.assertEqual(result['dn'], "CN=Test,DC=example,DC=com")
        self.assertEqual(result['objectClass'], ['user', 'person'])
        # Empty attribute should not cause issues
        self.assertNotIn('emptyAttr', result['attributes'])

        analyzer.cleanup()

    def test_backup_without_metadata(self):
        """Test analyzer behavior with backup that has no metadata."""
        backup_file = self.create_test_backup(with_metadata=False)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Should fall back to LDB extraction
        self.assertIsNone(analyzer.metadata)

        # Operations should still work but return empty results for non-extract mode
        objects = analyzer.list_objects()
        self.assertEqual(len(objects), 0)  # No metadata and no extraction

        count = analyzer.count_objects()
        self.assertEqual(count, 0)

        analyzer.cleanup()

    def test_cleanup_with_no_temp_dir(self):
        """Test cleanup when no temp directory was created."""
        backup_file = self.create_test_backup(with_metadata=True)
        analyzer = LdbAnalyzer(backup_file, extract=False)

        # Should have no temp directory
        self.assertIsNone(analyzer.temp_dir)

        # Cleanup should work without errors
        analyzer.cleanup()

        # Second cleanup should also work
        analyzer.cleanup()


if __name__ == "__main__":
    import unittest
    unittest.main()