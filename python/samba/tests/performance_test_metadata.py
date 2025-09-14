#!/usr/bin/env python3
# Performance testing for backup metadata collection
#
# This script tests the performance impact of metadata collection
# with various dataset sizes to ensure acceptable overhead.

import time
import tempfile
import os
import logging
from typing import Dict, List

# Import our modules
import sys
sys.path.insert(0, '/home/bulat/code/astra/samba/python')

from samba.backup_metadata import BackupMetadata
from samba.ldb_analyzer import LdbAnalyzer
import ldb


def create_test_database(num_objects: int) -> str:
    """Create a test LDB database with the specified number of objects."""
    temp_dir = tempfile.mkdtemp(prefix="perf_test_")
    db_path = os.path.join(temp_dir, "test.ldb")

    # Create test database
    test_ldb = ldb.Ldb(db_path)

    # Add base objects
    base_dn = "DC=test,DC=example,DC=com"
    try:
        test_ldb.add({
            "dn": base_dn,
            "objectClass": ["top", "domain"],
            "dc": "test"
        })
    except ldb.LdbError:
        pass  # May already exist

    # Add containers
    containers = [
        "CN=Users," + base_dn,
        "CN=Groups," + base_dn,
        "OU=TestOU," + base_dn
    ]

    for container in containers:
        try:
            test_ldb.add({
                "dn": container,
                "objectClass": ["top", "organizationalUnit"],
                "ou": container.split(",")[0].split("=")[1]
            })
        except ldb.LdbError:
            pass

    # Add test objects
    for i in range(num_objects):
        try:
            test_ldb.add({
                "dn": f"CN=testuser{i:04d},CN=Users," + base_dn,
                "objectClass": ["top", "person", "user"],
                "cn": f"testuser{i:04d}",
                "sAMAccountName": f"testuser{i:04d}",
                "description": f"Test user {i} for performance testing"
            })
        except ldb.LdbError:
            continue  # Skip duplicates

    return db_path


def measure_metadata_collection(db_path: str) -> Dict[str, float]:
    """Measure the time taken for metadata collection operations."""
    results = {}

    # Open database
    test_ldb = ldb.Ldb(db_path, flags=ldb.FLG_DONT_CREATE_DB)

    # Test BackupMetadata collection
    start_time = time.time()
    backup_metadata = BackupMetadata(test_ldb, backup_type="performance_test")
    backup_metadata.collect_domain_info()
    object_count = backup_metadata.collect_all_objects()
    end_time = time.time()

    results['metadata_collection_time'] = end_time - start_time
    results['objects_processed'] = object_count
    results['objects_per_second'] = object_count / (end_time - start_time) if (end_time - start_time) > 0 else 0

    # Test metadata export
    start_time = time.time()
    metadata_json = backup_metadata.to_json()
    end_time = time.time()

    results['json_export_time'] = end_time - start_time
    results['json_size_kb'] = len(metadata_json) / 1024

    # Test metadata file save
    temp_file = tempfile.mktemp(suffix=".json")
    start_time = time.time()
    backup_metadata.save_to_file(temp_file)
    end_time = time.time()

    results['file_save_time'] = end_time - start_time

    # Cleanup
    os.unlink(temp_file)

    return results


def measure_ldb_analysis(backup_file: str) -> Dict[str, float]:
    """Measure LDB analysis performance with a simulated backup."""
    results = {}

    # Create a simple tar file with the LDB
    import tarfile
    temp_backup = tempfile.mktemp(suffix=".tar.bz2")

    with tarfile.open(temp_backup, 'w:bz2') as tar:
        tar.add(backup_file, arcname="test.ldb")

    try:
        # Test LdbAnalyzer without extraction (metadata mode)
        start_time = time.time()
        analyzer = LdbAnalyzer(temp_backup, extract=False)
        # This will fall back to direct analysis since no metadata
        objects = analyzer.list_objects()
        end_time = time.time()

        results['analyzer_metadata_mode_time'] = end_time - start_time
        results['analyzer_objects_found'] = len(objects)

        analyzer.cleanup()

        # Test LdbAnalyzer with extraction
        start_time = time.time()
        analyzer = LdbAnalyzer(temp_backup, extract=True)
        objects = analyzer.list_objects()
        end_time = time.time()

        results['analyzer_extraction_mode_time'] = end_time - start_time
        results['analyzer_extraction_objects_found'] = len(objects)

        analyzer.cleanup()

    finally:
        if os.path.exists(temp_backup):
            os.unlink(temp_backup)

    return results


def run_performance_tests() -> Dict[int, Dict[str, float]]:
    """Run performance tests with various dataset sizes."""
    test_sizes = [10, 50, 100, 500, 1000, 2000]
    results = {}

    print("Backup Metadata Performance Testing")
    print("===================================")
    print()

    for size in test_sizes:
        print(f"Testing with {size} objects...")

        # Create test database
        db_path = create_test_database(size)

        try:
            # Measure metadata collection
            metadata_results = measure_metadata_collection(db_path)

            # Measure analysis performance
            analysis_results = measure_ldb_analysis(db_path)

            # Combine results
            combined_results = {**metadata_results, **analysis_results}
            results[size] = combined_results

            print(f"  Metadata collection: {metadata_results['metadata_collection_time']:.3f}s "
                  f"({metadata_results['objects_per_second']:.1f} obj/sec)")
            print(f"  JSON export: {metadata_results['json_export_time']:.3f}s "
                  f"({metadata_results['json_size_kb']:.1f} KB)")
            print(f"  Analysis (metadata): {analysis_results['analyzer_metadata_mode_time']:.3f}s")
            print(f"  Analysis (extraction): {analysis_results['analyzer_extraction_mode_time']:.3f}s")
            print()

        finally:
            # Cleanup test database
            try:
                os.unlink(db_path)
                os.rmdir(os.path.dirname(db_path))
            except:
                pass

    return results


def generate_performance_report(results: Dict[int, Dict[str, float]]) -> str:
    """Generate a performance report from test results."""
    report = []
    report.append("Backup Metadata Performance Report")
    report.append("=" * 50)
    report.append("")

    report.append("Dataset Size Performance:")
    report.append("-" * 30)
    report.append("Objects | Metadata | JSON | Analysis (Meta) | Analysis (Extract)")
    report.append("--------|----------|------|----------------|------------------")

    for size, data in sorted(results.items()):
        report.append(f"{size:7d} | "
                     f"{data['metadata_collection_time']:8.3f} | "
                     f"{data['json_export_time']:4.3f} | "
                     f"{data['analyzer_metadata_mode_time']:14.3f} | "
                     f"{data['analyzer_extraction_mode_time']:16.3f}")

    report.append("")
    report.append("Performance Summary:")
    report.append("-" * 20)

    # Calculate efficiency metrics
    if results:
        max_size = max(results.keys())
        max_data = results[max_size]

        report.append(f"Maximum tested dataset: {max_size} objects")
        report.append(f"Metadata collection rate: {max_data['objects_per_second']:.1f} objects/second")
        report.append(f"JSON size efficiency: {max_data['json_size_kb'] / max_size:.2f} KB/object")

        # Calculate overhead percentage (comparing extraction vs metadata modes)
        if max_data['analyzer_extraction_mode_time'] > 0:
            overhead = ((max_data['analyzer_metadata_mode_time'] /
                        max_data['analyzer_extraction_mode_time']) - 1) * 100
            report.append(f"Metadata mode performance advantage: {abs(overhead):.1f}% faster")

    report.append("")
    report.append("Recommendations:")
    report.append("-" * 15)
    if results and max_size >= 1000:
        if max_data['metadata_collection_time'] < 5.0:
            report.append("✓ Metadata collection overhead is acceptable for production use")
        else:
            report.append("⚠ Consider optimization for large datasets")

        if max_data['analyzer_metadata_mode_time'] < max_data['analyzer_extraction_mode_time']:
            report.append("✓ Metadata-based analysis provides significant performance benefits")
        else:
            report.append("⚠ Metadata analysis not showing expected performance benefits")
    else:
        report.append("ℹ Test with larger datasets (>1000 objects) for production assessment")

    return "\n".join(report)


if __name__ == "__main__":
    # Configure logging to reduce noise during testing
    logging.basicConfig(level=logging.WARNING)

    try:
        # Run performance tests
        test_results = run_performance_tests()

        # Generate and display report
        report = generate_performance_report(test_results)
        print(report)

        # Save report to file
        report_file = "/tmp/backup_metadata_performance_report.txt"
        with open(report_file, 'w') as f:
            f.write(report)

        print(f"\nFull report saved to: {report_file}")

    except Exception as e:
        print(f"Performance testing failed: {e}")
        import traceback
        traceback.print_exc()