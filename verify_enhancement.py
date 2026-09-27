from modules.hidden_asset_scanner import HiddenAssetScanner, HIDDEN_PATHS, BACKUP_EXTENSIONS
print("HiddenAssetScanner import: OK")

from modules.ai_integration import AIIntegration
engine = AIIntegration()
assert "hidden_asset_scanner" in engine.PROMPTS
assert "post_exploitation_validation" in engine.PROMPTS
assert "aggressive_confirmation" in engine.PROMPTS
print("New prompt templates: OK")

import re
NEGATION = re.compile(r"never|not\b|must not|no\b", re.IGNORECASE)
for key in ["hidden_asset_scanner", "post_exploitation_validation", "aggressive_confirmation"]:
    prompt = engine.PROMPTS[key]
    for m in re.finditer(r"minor", prompt, re.IGNORECASE):
        window = prompt[max(0, m.start() - 90):m.end() + 90]
        assert NEGATION.search(window), f"{key}: 'minor' used without negation: ...{window}..."
print("'minor' only ever used in negation context: OK")

from modules.post_exploitation.enumeration import SystemEnumerator
assert hasattr(SystemEnumerator, "_enum_hidden_files_linux")
assert hasattr(SystemEnumerator, "_enum_backup_files_linux")
assert hasattr(SystemEnumerator, "_enum_misconfigurations_linux")
assert hasattr(SystemEnumerator, "_enum_hidden_files_windows")
assert hasattr(SystemEnumerator, "_enum_backup_files_windows")
assert hasattr(SystemEnumerator, "_enum_misconfigurations_windows")
print("Post-exploitation methods: OK")

scanner = HiddenAssetScanner()
assert scanner._classify_path("/.git/") == "version_control"
assert scanner._classify_path("/.env") == "environment_config"
assert scanner._classify_path("/config.php.bak") == "backup_file"
assert scanner._determine_severity("/.git/", {}) == "CRITICAL"
assert scanner._determine_severity("/.htaccess", {}) == "HIGH"
print("Classification and severity: OK")

assert len(HIDDEN_PATHS) > 50
assert "/.git" in HIDDEN_PATHS
assert "/.env" in HIDDEN_PATHS
print(f"HIDDEN_PATHS count: {len(HIDDEN_PATHS)}")

assert ".bak" in BACKUP_EXTENSIONS
assert ".sql" in BACKUP_EXTENSIONS
assert ".zip" in BACKUP_EXTENSIONS
print(f"BACKUP_EXTENSIONS count: {len(BACKUP_EXTENSIONS)}")

print("\nALL CHECKS PASSED")
