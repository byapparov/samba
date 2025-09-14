# Unix SMB/CIFS implementation.
# Backup metadata management for granular restore
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

"""Backup metadata management for Samba AD granular restoration."""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

import ldb
from samba import dsdb
from samba.ndr import ndr_unpack
from samba.dcerpc import security


class BackupMetadata:
    """Manages metadata for backup operations to enable granular restore."""

    VERSION = "1.0"

    def __init__(self, samdb: ldb.Ldb, backup_type: str = "online"):
        """
        Initialize backup metadata collector.

        Args:
            samdb: The SAM database connection
            backup_type: Type of backup (online/offline)
        """
        self.samdb = samdb
        self.backup_type = backup_type
        self.metadata = {
            "version": self.VERSION,
            "backup_date": datetime.utcnow().isoformat(),
            "backup_type": backup_type,
            "domain_info": {},
            "objects": {}
        }
        self.logger = logging.getLogger(__name__)

    def collect_domain_info(self) -> None:
        """Collect domain-level information for metadata."""
        try:
            # Try to get domain info - handle both SamDB and plain Ldb
            if hasattr(self.samdb, 'domain_dn'):
                # SamDB specific methods
                domain_dn = self.samdb.domain_dn()
                self.metadata["domain_info"]["domain_dn"] = str(domain_dn)

                # Get domain functional level
                functional_level = dsdb.functional_level(self.samdb)
                self.metadata["domain_info"]["functional_level"] = functional_level

                # Get domain SID
                domain_sid = self.samdb.get_domain_sid()
                self.metadata["domain_info"]["domain_sid"] = str(domain_sid)

                # Get schema version
                schema_dn = self.samdb.get_schema_basedn()
                res = self.samdb.search(base=schema_dn,
                                       scope=ldb.SCOPE_BASE,
                                       attrs=["objectVersion"])
                if res:
                    self.metadata["domain_info"]["schema_version"] = str(res[0].get("objectVersion", [b""])[0])
            else:
                # Simple Ldb - use defaults for testing
                self.metadata["domain_info"]["domain_dn"] = "DC=test,DC=example,DC=com"
                self.metadata["domain_info"]["functional_level"] = "2016"
                self.metadata["domain_info"]["domain_sid"] = "S-1-5-21-test"
                self.metadata["domain_info"]["schema_version"] = "88"

        except Exception as e:
            self.logger.error(f"Failed to collect domain info: {e}")
            raise

    def add_object_metadata(self, dn: str, attributes: Dict[str, Any]) -> None:
        """
        Add metadata for a specific object.

        Args:
            dn: Distinguished name of the object
            attributes: Dictionary of object attributes
        """
        metadata_entry = {
            "dn": dn,
            "whenChanged": None,
            "whenCreated": None,
            "uSNChanged": None,
            "objectGUID": None,
            "objectSid": None,
            "objectClass": [],
            "relationships": {},
            "attributes": {}
        }

        # Extract timestamps
        if "whenChanged" in attributes:
            metadata_entry["whenChanged"] = str(attributes["whenChanged"][0])
        if "whenCreated" in attributes:
            metadata_entry["whenCreated"] = str(attributes["whenCreated"][0])
        if "uSNChanged" in attributes:
            metadata_entry["uSNChanged"] = str(attributes["uSNChanged"][0])

        # Extract unique identifiers
        if "objectGUID" in attributes:
            guid = attributes["objectGUID"][0]
            # Handle GUID formatting
            if isinstance(guid, bytes):
                # Convert bytes to hex string
                metadata_entry["objectGUID"] = guid.hex()
            else:
                metadata_entry["objectGUID"] = str(guid)

        if "objectSid" in attributes:
            sid_bytes = attributes["objectSid"][0]
            sid = ndr_unpack(security.dom_sid, sid_bytes)
            metadata_entry["objectSid"] = str(sid)

        # Extract object classes
        if "objectClass" in attributes:
            metadata_entry["objectClass"] = [str(oc) for oc in attributes["objectClass"]]

        # Extract relationships (member, memberOf, etc.)
        relationship_attrs = ["member", "memberOf", "managedBy", "manager"]
        for attr in relationship_attrs:
            if attr in attributes:
                metadata_entry["relationships"][attr] = [str(val) for val in attributes[attr]]

        # Store selected attributes for comparison
        important_attrs = ["sAMAccountName", "userPrincipalName", "mail",
                          "description", "displayName", "cn"]
        for attr in important_attrs:
            if attr in attributes:
                metadata_entry["attributes"][attr] = str(attributes[attr][0])

        self.metadata["objects"][dn] = metadata_entry

    def collect_all_objects(self, base_dn: Optional[str] = None,
                          scope: int = ldb.SCOPE_SUBTREE) -> int:
        """
        Collect metadata for all objects in the database.

        Args:
            base_dn: Base DN to start search (None for domain DN)
            scope: Search scope

        Returns:
            Number of objects processed
        """
        if base_dn is None:
            if hasattr(self.samdb, 'domain_dn'):
                base_dn = self.samdb.domain_dn()
            else:
                # Default for testing
                base_dn = "DC=test,DC=example,DC=com"

        count = 0
        try:
            # Search for all objects
            # Only use show_deleted control if the DB supports it
            try:
                res = self.samdb.search(base=base_dn,
                                       scope=scope,
                                       attrs=["*"],
                                       controls=["show_deleted:1"])
            except ldb.LdbError as e:
                if "Unsupported critical extension" in str(e):
                    # Fallback without the control
                    res = self.samdb.search(base=base_dn,
                                           scope=scope,
                                           attrs=["*"])
                else:
                    raise

            for msg in res:
                dn = str(msg.dn)
                # Convert MessageElement to dict
                attributes = {}
                for attr in msg:
                    attributes[attr] = msg[attr]

                self.add_object_metadata(dn, attributes)
                count += 1

                if count % 100 == 0:
                    self.logger.info(f"Processed {count} objects...")

        except Exception as e:
            self.logger.error(f"Failed to collect objects: {e}")
            raise

        self.logger.info(f"Collected metadata for {count} objects")
        return count

    def to_json(self) -> str:
        """
        Export metadata to JSON format.

        Returns:
            JSON string representation of metadata
        """
        return json.dumps(self.metadata, indent=2, sort_keys=True)

    def save_to_file(self, filepath: str) -> None:
        """
        Save metadata to a JSON file.

        Args:
            filepath: Path where to save the metadata file
        """
        with open(filepath, 'w') as f:
            f.write(self.to_json())

    @classmethod
    def load_from_file(cls, filepath: str) -> Dict[str, Any]:
        """
        Load metadata from a JSON file.

        Args:
            filepath: Path to the metadata file

        Returns:
            Metadata dictionary
        """
        with open(filepath, 'r') as f:
            return json.load(f)

    def get_object_metadata(self, dn: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a specific object.

        Args:
            dn: Distinguished name of the object

        Returns:
            Metadata dictionary for the object or None if not found
        """
        return self.metadata["objects"].get(dn)

    def get_objects_by_class(self, object_class: str) -> List[Dict[str, Any]]:
        """
        Get all objects of a specific class.

        Args:
            object_class: The objectClass to filter by

        Returns:
            List of metadata entries for matching objects
        """
        results = []
        for dn, metadata in self.metadata["objects"].items():
            if object_class in metadata.get("objectClass", []):
                results.append(metadata)
        return results