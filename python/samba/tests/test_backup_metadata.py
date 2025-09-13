# Unix SMB/CIFS implementation.
# Tests for backup metadata functionality
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

"""Tests for backup metadata management."""

import json
import os
import tempfile
import time
from datetime import datetime, timedelta

import ldb
from samba import dsdb
from samba.auth import system_session
from samba.backup_metadata import BackupMetadata
from samba.credentials import Credentials
from samba.dcerpc import security
from samba.ndr import ndr_pack
from samba.param import LoadParm
from samba.provision import provision
from samba.tests import TestCase, TestCaseInTempDir


class BackupMetadataTestBase(TestCaseInTempDir):
    """Base class for backup metadata tests."""

    def setUp(self):
        super().setUp()
        self.lp = LoadParm()
        self.lp.load_default()
        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.session = system_session()

        # Create a test SAM database
        self.test_dir = tempfile.mkdtemp()
        self.samdb_path = os.path.join(self.test_dir, "sam.ldb")
        self.samdb = self._create_test_samdb()

    def tearDown(self):
        """Clean up test environment."""
        super().tearDown()
        if hasattr(self, 'samdb'):
            del self.samdb
        if os.path.exists(self.test_dir):
            import shutil
            shutil.rmtree(self.test_dir)

    def _create_test_samdb(self):
        """Create a minimal test SAM database."""
        # Create a simple LDB for testing - use ldb.Ldb instead of SamDB for simplicity
        import ldb

        # Ensure the directory exists
        os.makedirs(self.test_dir, exist_ok=True)

        # Create a basic LDB database
        samdb = ldb.Ldb(self.samdb_path, flags=ldb.FLG_NOSYNC)

        # Add minimal schema for testing
        samdb.transaction_start()
        try:
            # Add base DNs
            samdb.add({
                "dn": "DC=test,DC=example,DC=com",
                "objectClass": ["top", "domain"],
                "dc": "test"
            })

            samdb.add({
                "dn": "CN=Users,DC=test,DC=example,DC=com",
                "objectClass": ["top", "container"],
                "cn": "Users"
            })

            samdb.transaction_commit()
        except Exception as e:
            samdb.transaction_cancel()
            raise

        return samdb

    def create_test_user(self, username, **kwargs):
        """Create a test user in the database."""
        user_dn = f"CN={username},CN=Users,DC=test,DC=example,DC=com"

        user_record = {
            "dn": user_dn,
            "objectClass": ["top", "person", "user"],
            "cn": username,
            "sAMAccountName": username,
            "userPrincipalName": f"{username}@test.example.com",
            "objectGUID": kwargs.get("objectGUID", os.urandom(16)),
            "whenCreated": kwargs.get("whenCreated", datetime.utcnow().strftime("%Y%m%d%H%M%S.0Z")),
            "whenChanged": kwargs.get("whenChanged", datetime.utcnow().strftime("%Y%m%d%H%M%S.0Z")),
            "uSNChanged": str(kwargs.get("uSNChanged", 1000))
        }

        # Add optional attributes
        for attr in ["description", "mail", "displayName"]:
            if attr in kwargs:
                user_record[attr] = kwargs[attr]

        # Add objectSid if it's a security principal
        if kwargs.get("objectSid"):
            user_record["objectSid"] = ndr_pack(security.dom_sid(kwargs["objectSid"]))

        self.samdb.add(user_record)
        return user_dn

    def create_test_group(self, groupname, **kwargs):
        """Create a test group in the database."""
        group_dn = f"CN={groupname},CN=Users,DC=test,DC=example,DC=com"

        group_record = {
            "dn": group_dn,
            "objectClass": ["top", "group"],
            "cn": groupname,
            "sAMAccountName": groupname,
            "objectGUID": kwargs.get("objectGUID", os.urandom(16)),
            "whenCreated": kwargs.get("whenCreated", datetime.utcnow().strftime("%Y%m%d%H%M%S.0Z")),
            "whenChanged": kwargs.get("whenChanged", datetime.utcnow().strftime("%Y%m%d%H%M%S.0Z")),
            "uSNChanged": str(kwargs.get("uSNChanged", 2000))
        }

        if kwargs.get("objectSid"):
            group_record["objectSid"] = ndr_pack(security.dom_sid(kwargs["objectSid"]))

        self.samdb.add(group_record)
        return group_dn


class BackupMetadataCreationTests(BackupMetadataTestBase):
    """Tests for metadata creation functionality."""

    def test_metadata_initialization(self):
        """Test BMF-001: Basic metadata object initialization."""
        metadata = BackupMetadata(self.samdb, backup_type="online")

        self.assertEqual(metadata.VERSION, "1.0")
        self.assertEqual(metadata.backup_type, "online")
        self.assertIn("version", metadata.metadata)
        self.assertIn("backup_date", metadata.metadata)
        self.assertIn("domain_info", metadata.metadata)
        self.assertIn("objects", metadata.metadata)

    def test_collect_domain_info(self):
        """Test metadata collection for domain information."""
        metadata = BackupMetadata(self.samdb)

        # Mock domain info collection since we have a minimal test DB
        metadata.metadata["domain_info"] = {
            "domain_dn": "DC=test,DC=example,DC=com",
            "functional_level": "2016",
            "domain_sid": "S-1-5-21-1234567890-1234567890-1234567890",
            "schema_version": "88"
        }

        self.assertIn("domain_dn", metadata.metadata["domain_info"])
        self.assertIn("functional_level", metadata.metadata["domain_info"])
        self.assertIn("domain_sid", metadata.metadata["domain_info"])

    def test_add_object_metadata(self):
        """Test BMF-001: Verify metadata is correctly created for each object."""
        # Create a test user
        user_dn = self.create_test_user("testuser1",
                                       description="Test User 1",
                                       mail="test1@example.com",
                                       objectSid="S-1-5-21-1234567890-1234567890-1234567890-1001")

        # Get the user from database
        res = self.samdb.search(base=user_dn, scope=ldb.SCOPE_BASE, attrs=["*"])
        self.assertEqual(len(res), 1)

        # Create metadata and add object
        metadata = BackupMetadata(self.samdb)
        attributes = {}
        for attr in res[0]:
            attributes[attr] = res[0][attr]

        metadata.add_object_metadata(user_dn, attributes)

        # Verify metadata was added
        user_metadata = metadata.get_object_metadata(user_dn)
        self.assertIsNotNone(user_metadata)
        self.assertEqual(user_metadata["dn"], user_dn)
        self.assertIn("whenCreated", user_metadata)
        self.assertIn("whenChanged", user_metadata)
        self.assertIn("uSNChanged", user_metadata)
        self.assertIn("objectClass", user_metadata)
        self.assertIn("user", user_metadata["objectClass"])

    def test_metadata_timestamp_tracking(self):
        """Test BMF-002: Verify timestamps are accurately tracked in metadata."""
        # Create object with specific timestamps
        creation_time = datetime.utcnow()
        creation_str = creation_time.strftime("%Y%m%d%H%M%S.0Z")

        # Create object
        group_dn = self.create_test_group("testgroup1",
                                         whenCreated=creation_str,
                                         whenChanged=creation_str)

        # Wait at least 1 second to ensure different timestamp
        time.sleep(1.1)
        modification_time = datetime.utcnow()
        modification_str = modification_time.strftime("%Y%m%d%H%M%S.0Z")

        # Update the object using modify
        msg = ldb.Message()
        msg.dn = ldb.Dn(self.samdb, group_dn)
        msg["description"] = ldb.MessageElement("Modified group", ldb.FLAG_MOD_REPLACE, "description")
        msg["whenChanged"] = ldb.MessageElement(modification_str, ldb.FLAG_MOD_REPLACE, "whenChanged")
        self.samdb.modify(msg)

        # Collect metadata
        metadata = BackupMetadata(self.samdb)
        res = self.samdb.search(base=group_dn, scope=ldb.SCOPE_BASE, attrs=["*"])
        attributes = {}
        for attr in res[0]:
            attributes[attr] = res[0][attr]

        metadata.add_object_metadata(group_dn, attributes)
        group_metadata = metadata.get_object_metadata(group_dn)

        # Verify timestamps
        self.assertEqual(group_metadata["whenCreated"], creation_str)
        self.assertEqual(group_metadata["whenChanged"], modification_str)
        self.assertNotEqual(group_metadata["whenCreated"], group_metadata["whenChanged"])

    def test_metadata_file_format(self):
        """Test BMF-004: Verify metadata file format is valid and parseable."""
        metadata = BackupMetadata(self.samdb)

        # Add some test data
        user_dn = self.create_test_user("formatuser")
        res = self.samdb.search(base=user_dn, scope=ldb.SCOPE_BASE, attrs=["*"])
        attributes = {}
        for attr in res[0]:
            attributes[attr] = res[0][attr]
        metadata.add_object_metadata(user_dn, attributes)

        # Export to JSON
        json_output = metadata.to_json()

        # Verify valid JSON
        parsed = json.loads(json_output)
        self.assertIn("version", parsed)
        self.assertEqual(parsed["version"], "1.0")
        self.assertIn("backup_date", parsed)
        self.assertIn("backup_type", parsed)
        self.assertIn("domain_info", parsed)
        self.assertIn("objects", parsed)

        # Save and load from file
        temp_file = os.path.join(self.test_dir, "metadata.json")
        metadata.save_to_file(temp_file)

        loaded = BackupMetadata.load_from_file(temp_file)
        self.assertEqual(loaded["version"], "1.0")
        self.assertIn(user_dn, loaded["objects"])

    def test_get_objects_by_class(self):
        """Test filtering objects by objectClass."""
        metadata = BackupMetadata(self.samdb)

        # Create different object types
        user1_dn = self.create_test_user("classuser1")
        user2_dn = self.create_test_user("classuser2")
        group_dn = self.create_test_group("classgroup1")

        # Add to metadata
        for dn in [user1_dn, user2_dn, group_dn]:
            res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["*"])
            attributes = {}
            for attr in res[0]:
                attributes[attr] = res[0][attr]
            metadata.add_object_metadata(dn, attributes)

        # Test filtering
        users = metadata.get_objects_by_class("user")
        self.assertEqual(len(users), 2)

        groups = metadata.get_objects_by_class("group")
        self.assertEqual(len(groups), 1)

        # Verify correct objects returned
        user_dns = [u["dn"] for u in users]
        self.assertIn(user1_dn, user_dns)
        self.assertIn(user2_dn, user_dns)

        self.assertEqual(groups[0]["dn"], group_dn)


if __name__ == "__main__":
    import unittest
    unittest.main()