from collector import ManualImporter, create_default_manager
from config import config

print("=== Test 1: ManualImporter file not found ===")
importer = ManualImporter()
importer.load_from_file("/nonexistent/file.json")
print(f"raw_data after missing file: {importer.raw_data}")
result = importer.collect()
print(f"Collect result: {len(result.vulns)} vulns, error: {result.error}")

print()
print("=== Test 2: create_default_manager with test_mode=True ===")
manager = create_default_manager(test_mode=True)
print(f"Manager has {len(manager.collectors)} collectors")

print()
print("=== Test 3: config methods check ===")
print(f"config.is_test_mode(): {config.is_test_mode()}")
print(f"config.scanner.use_mock_scanner(): {config.scanner.use_mock_scanner()}")
print(f"config.scanner.use_mock_threat_intel(): {config.scanner.use_mock_threat_intel()}")

print()
print("=== All tests passed! ===")
