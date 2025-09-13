# Unix SMB/CIFS implementation.
# LDB file analyzer for granular backup operations
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

"""LDB file analyzer for examining backup contents without restoration."""

import os
import tempfile
import logging
from typing import Dict, List, Any, Optional, Union
import json
try:
    # Try using safe_tarfile if available
    from samba import safe_tarfile as tarfile
except ImportError:
    # Fallback to standard tarfile
    import tarfile

import ldb
from samba.ndr import ndr_unpack
from samba.dcerpc import security


class LdbAnalyzer:
    """Analyzes LDB files from backups without requiring full restoration."""

    def __init__(self, backup_file: str, extract: bool = False):
        """
        Initialize the LDB analyzer.

        Args:
            backup_file: Path to the backup file (tar.bz2)
            extract: Whether to extract the backup (False for in-memory analysis)
        """
        self.backup_file = backup_file
        self.extract = extract
        self.logger = logging.getLogger(__name__)
        self.ldb_connections = {}
        self.temp_dir = None
        self.metadata = None

        # Open the backup and prepare for analysis
        self._prepare_backup()

    def _prepare_backup(self):
        """Prepare the backup for analysis."""
        if not os.path.exists(self.backup_file):
            raise FileNotFoundError(f"Backup file not found: {self.backup_file}")

        if self.extract:
            # Extract to temporary directory
            self.temp_dir = tempfile.mkdtemp(prefix="ldb_analyzer_")
            with tarfile.open(self.backup_file, 'r:bz2') as tar:
                tar.extractall(self.temp_dir)

            # Find and open LDB files
            self._open_ldb_files()
        else:
            # For non-extraction mode, we'll work with tar file directly
            self._analyze_tar_contents()

    def _open_ldb_files(self):
        """Open LDB files from extracted backup."""
        if not self.temp_dir:
            return

        # Find all .ldb files
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith('.ldb'):
                    ldb_path = os.path.join(root, file)
                    try:
                        # Open in read-only mode
                        ldb_conn = ldb.Ldb(ldb_path, flags=ldb.FLG_RDONLY)
                        ldb_name = os.path.basename(ldb_path)
                        self.ldb_connections[ldb_name] = ldb_conn
                        self.logger.info(f"Opened LDB file: {ldb_name}")
                    except Exception as e:
                        self.logger.warning(f"Could not open LDB {ldb_path}: {e}")

    def _analyze_tar_contents(self):
        """Analyze backup contents without extraction."""
        with tarfile.open(self.backup_file, 'r:bz2') as tar:
            # Look for metadata file first
            for member in tar.getmembers():
                if member.name.endswith('metadata.json'):
                    metadata_file = tar.extractfile(member)
                    if metadata_file:
                        self.metadata = json.loads(metadata_file.read().decode('utf-8'))
                        break

    def list_objects(self, object_class: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List objects in the backup without restoration.

        Args:
            object_class: Optional filter by objectClass

        Returns:
            List of object dictionaries
        """
        objects = []

        # If we have metadata, use it (fastest)
        if self.metadata and 'objects' in self.metadata:
            for dn, obj_meta in self.metadata['objects'].items():
                if object_class:
                    if object_class not in obj_meta.get('objectClass', []):
                        continue
                objects.append({
                    'dn': dn,
                    'objectClass': obj_meta.get('objectClass', []),
                    'objectGUID': obj_meta.get('objectGUID'),
                    'objectSid': obj_meta.get('objectSid'),
                    'whenChanged': obj_meta.get('whenChanged')
                })

        # Otherwise, query LDB files if extracted
        elif self.ldb_connections:
            for ldb_name, ldb_conn in self.ldb_connections.items():
                try:
                    # Search for objects
                    filter_str = f"(objectClass={object_class})" if object_class else "(objectClass=*)"
                    res = ldb_conn.search(base="", scope=ldb.SCOPE_SUBTREE,
                                         expression=filter_str,
                                         attrs=["objectClass", "objectGUID", "objectSid", "whenChanged"])

                    for msg in res:
                        obj = {
                            'dn': str(msg.dn),
                            'objectClass': [str(oc) for oc in msg.get('objectClass', [])],
                            'source': ldb_name
                        }

                        if 'objectGUID' in msg:
                            obj['objectGUID'] = msg['objectGUID'][0].hex()
                        if 'objectSid' in msg:
                            obj['objectSid'] = str(ndr_unpack(security.dom_sid, msg['objectSid'][0]))
                        if 'whenChanged' in msg:
                            obj['whenChanged'] = str(msg['whenChanged'][0])

                        objects.append(obj)

                except Exception as e:
                    self.logger.error(f"Error searching {ldb_name}: {e}")

        return objects

    def search_by_dn(self, dn: str, scope: str = 'base') -> Optional[Dict[str, Any]]:
        """
        Search for object by Distinguished Name.

        Args:
            dn: Distinguished Name to search for
            scope: Search scope ('base', 'onelevel', 'subtree')

        Returns:
            Object dictionary or None if not found
        """
        # Check metadata first
        if self.metadata and 'objects' in self.metadata:
            if scope == 'base':
                obj_meta = self.metadata['objects'].get(dn)
                if obj_meta:
                    return obj_meta
            else:
                # For subtree/onelevel searches
                results = []
                for obj_dn, obj_meta in self.metadata['objects'].items():
                    if scope == 'subtree' and obj_dn.endswith(dn):
                        results.append(obj_meta)
                    elif scope == 'onelevel':
                        # Check if it's a direct child
                        if ',' in obj_dn:
                            parent_dn = obj_dn.split(',', 1)[1]
                            if parent_dn == dn:
                                results.append(obj_meta)
                return results if results else None

        # Search in LDB files
        if self.ldb_connections:
            for ldb_name, ldb_conn in self.ldb_connections.items():
                try:
                    scope_map = {
                        'base': ldb.SCOPE_BASE,
                        'onelevel': ldb.SCOPE_ONELEVEL,
                        'subtree': ldb.SCOPE_SUBTREE
                    }
                    res = ldb_conn.search(base=dn, scope=scope_map.get(scope, ldb.SCOPE_BASE))

                    if res:
                        if scope == 'base':
                            return self._message_to_dict(res[0])
                        else:
                            return [self._message_to_dict(msg) for msg in res]

                except Exception as e:
                    self.logger.debug(f"DN {dn} not found in {ldb_name}: {e}")

        return None

    def search_by_guid(self, guid: Union[str, bytes]) -> Optional[Dict[str, Any]]:
        """
        Search for object by GUID.

        Args:
            guid: GUID as string or bytes

        Returns:
            Object dictionary or None if not found
        """
        # Normalize GUID to hex string
        if isinstance(guid, bytes):
            guid_hex = guid.hex()
        else:
            # Remove any hyphens and convert to lowercase
            guid_hex = guid.replace('-', '').lower()

        # Validate GUID format
        if len(guid_hex) != 32:
            raise ValueError(f"Invalid GUID format: {guid}")
        try:
            int(guid_hex, 16)  # Validate it's hex
        except ValueError:
            raise ValueError(f"Invalid GUID format: {guid}")

        # Check metadata
        if self.metadata and 'objects' in self.metadata:
            for dn, obj_meta in self.metadata['objects'].items():
                if obj_meta.get('objectGUID', '').lower() == guid_hex:
                    return obj_meta

        # Search in LDB files
        if self.ldb_connections:
            for ldb_name, ldb_conn in self.ldb_connections.items():
                try:
                    # Search by objectGUID
                    res = ldb_conn.search(base="", scope=ldb.SCOPE_SUBTREE,
                                         expression=f"(objectGUID={guid_hex})")
                    if res:
                        return self._message_to_dict(res[0])
                except Exception as e:
                    self.logger.debug(f"GUID search failed in {ldb_name}: {e}")

        return None

    def search_by_sid(self, sid: Union[str, object]) -> Optional[Dict[str, Any]]:
        """
        Search for object by Security Identifier.

        Args:
            sid: SID as string or security.dom_sid object

        Returns:
            Object dictionary or None if not found
        """
        # Normalize SID to string
        sid_str = str(sid)

        # Check metadata
        if self.metadata and 'objects' in self.metadata:
            for dn, obj_meta in self.metadata['objects'].items():
                if obj_meta.get('objectSid') == sid_str:
                    return obj_meta

        # Search in LDB files
        if self.ldb_connections:
            for ldb_name, ldb_conn in self.ldb_connections.items():
                try:
                    # Search by objectSid
                    res = ldb_conn.search(base="", scope=ldb.SCOPE_SUBTREE,
                                         expression=f"(objectSid={sid_str})")
                    if res:
                        return self._message_to_dict(res[0])
                except Exception as e:
                    self.logger.debug(f"SID search failed in {ldb_name}: {e}")

        return None

    def get_object_attributes(self, dn: str) -> Optional[Dict[str, Any]]:
        """
        Get all attributes for an object.

        Args:
            dn: Distinguished Name of the object

        Returns:
            Dictionary of attributes or None if not found
        """
        # Try metadata first
        if self.metadata and 'objects' in self.metadata:
            obj_meta = self.metadata['objects'].get(dn)
            if obj_meta:
                return obj_meta.get('attributes', {})

        # Query LDB files
        if self.ldb_connections:
            for ldb_name, ldb_conn in self.ldb_connections.items():
                try:
                    res = ldb_conn.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["*"])
                    if res:
                        return self._message_to_dict(res[0])
                except Exception:
                    continue

        return None

    def filter_by_objectclass(self, object_class: Union[str, List[str]]) -> List[Dict[str, Any]]:
        """
        Filter objects by objectClass.

        Args:
            object_class: Single class or list of classes

        Returns:
            List of matching objects
        """
        if isinstance(object_class, str):
            object_classes = [object_class]
        else:
            object_classes = object_class

        results = []

        # Check metadata
        if self.metadata and 'objects' in self.metadata:
            for dn, obj_meta in self.metadata['objects'].items():
                obj_classes = obj_meta.get('objectClass', [])
                if any(oc in obj_classes for oc in object_classes):
                    results.append(obj_meta)

        # Search LDB files
        elif self.ldb_connections:
            for oc in object_classes:
                objs = self.list_objects(object_class=oc)
                results.extend(objs)

        return results

    def export_to_ldif(self, dn: str) -> Optional[str]:
        """
        Export object to LDIF format.

        Args:
            dn: Distinguished Name of the object

        Returns:
            LDIF string or None if not found
        """
        obj = self.search_by_dn(dn)
        if not obj:
            return None

        # Build LDIF
        ldif_lines = [f"dn: {dn}"]

        # Add objectClass entries
        for oc in obj.get('objectClass', []):
            ldif_lines.append(f"objectClass: {oc}")

        # Add other attributes
        for attr, value in obj.get('attributes', {}).items():
            if attr != 'objectClass':
                ldif_lines.append(f"{attr}: {value}")

        # Add special attributes
        if 'objectGUID' in obj:
            ldif_lines.append(f"objectGUID: {obj['objectGUID']}")
        if 'objectSid' in obj:
            ldif_lines.append(f"objectSid: {obj['objectSid']}")

        return '\n'.join(ldif_lines)

    def count_objects(self) -> int:
        """
        Count total objects in the backup.

        Returns:
            Number of objects
        """
        if self.metadata and 'objects' in self.metadata:
            return len(self.metadata['objects'])

        count = 0
        if self.ldb_connections:
            for ldb_name, ldb_conn in self.ldb_connections.items():
                try:
                    res = ldb_conn.search(base="", scope=ldb.SCOPE_SUBTREE,
                                         expression="(objectClass=*)")
                    count += len(res)
                except Exception as e:
                    self.logger.error(f"Error counting objects in {ldb_name}: {e}")

        return count

    def compare_with(self, other_analyzer: 'LdbAnalyzer') -> Dict[str, List[str]]:
        """
        Compare this backup with another backup.

        Args:
            other_analyzer: Another LdbAnalyzer instance

        Returns:
            Dictionary with 'added', 'modified', 'deleted' lists
        """
        differences = {
            'added': [],
            'modified': {},
            'deleted': []
        }

        # Get object lists from both backups
        this_objects = {obj['dn']: obj for obj in self.list_objects()}
        other_objects = {obj['dn']: obj for obj in other_analyzer.list_objects()}

        # Find added objects
        for dn in other_objects:
            if dn not in this_objects:
                differences['added'].append(dn)

        # Find deleted objects
        for dn in this_objects:
            if dn not in other_objects:
                differences['deleted'].append(dn)

        # Find modified objects
        for dn in this_objects:
            if dn in other_objects:
                this_obj = this_objects[dn]
                other_obj = other_objects[dn]

                # Compare whenChanged timestamps
                if this_obj.get('whenChanged') != other_obj.get('whenChanged'):
                    differences['modified'][dn] = {
                        'old': this_obj.get('whenChanged'),
                        'new': other_obj.get('whenChanged')
                    }

        return differences

    def _message_to_dict(self, msg: ldb.Message) -> Dict[str, Any]:
        """Convert LDB message to dictionary."""
        result = {
            'dn': str(msg.dn),
            'attributes': {}
        }

        for attr in msg:
            if attr == 'objectClass':
                result['objectClass'] = [str(oc) for oc in msg[attr]]
            elif attr == 'objectGUID':
                result['objectGUID'] = msg[attr][0].hex()
            elif attr == 'objectSid':
                result['objectSid'] = str(ndr_unpack(security.dom_sid, msg[attr][0]))
            else:
                # Store first value for simplicity
                if msg[attr]:
                    result['attributes'][attr] = str(msg[attr][0])

        return result

    def cleanup(self):
        """Clean up temporary files and connections."""
        # Close LDB connections
        for ldb_conn in self.ldb_connections.values():
            try:
                del ldb_conn
            except:
                pass
        self.ldb_connections.clear()

        # Remove temporary directory
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None

    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup()