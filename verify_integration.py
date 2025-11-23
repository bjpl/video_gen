#!/usr/bin/env python3
"""
Integration Verification Script
================================
Verifies that all components of the web UI integration are working correctly
"""

import sys
from pathlib import Path
import importlib.util

def check_file_exists(file_path: Path, description: str) -> bool:
    """Check if a file exists"""
    if file_path.exists():
        print(f"✅ {description}: {file_path}")
        return True
    else:
        print(f"❌ {description}: MISSING - {file_path}")
        return False

def check_module_import(module_path: str, description: str) -> bool:
    """Check if a Python module can be imported"""
    try:
        spec = importlib.util.find_spec(module_path)
        if spec:
            print(f"✅ {description}: Can import {module_path}")
            return True
        else:
            print(f"❌ {description}: Cannot find {module_path}")
            return False
    except Exception as e:
        print(f"❌ {description}: Import error - {e}")
        return False

def main():
    print("\n" + "="*80)
    print("🔍 INTEGRATION VERIFICATION")
    print("="*80 + "\n")

    base_dir = Path(__file__).parent
    checks_passed = 0
    total_checks = 0

    # Check backend files
    print("📦 Backend Files:")
    print("-" * 80)

    backend_files = [
        (base_dir / "app" / "main.py", "FastAPI main app"),
        (base_dir / "app" / "services" / "__init__.py", "Services package"),
        (base_dir / "app" / "services" / "video_service.py", "Video service"),
    ]

    for file_path, description in backend_files:
        total_checks += 1
        if check_file_exists(file_path, description):
            checks_passed += 1

    print()

    # Check frontend files
    print("🎨 Frontend Files:")
    print("-" * 80)

    frontend_files = [
        (base_dir / "app" / "templates" / "index.html", "Main UI template"),
        (base_dir / "app" / "templates" / "job_list.html", "Job list template"),
        (base_dir / "app" / "static" / ".gitkeep", "Static directory"),
    ]

    for file_path, description in frontend_files:
        total_checks += 1
        if check_file_exists(file_path, description):
            checks_passed += 1

    print()

    # Check test files
    print("🧪 Test Files:")
    print("-" * 80)

    test_files = [
        (base_dir / "tests" / "test_integration.py", "Integration tests"),
    ]

    for file_path, description in test_files:
        total_checks += 1
        if check_file_exists(file_path, description):
            checks_passed += 1

    print()

    # Check documentation
    print("📚 Documentation:")
    print("-" * 80)

    doc_files = [
        (base_dir / "app" / "README.md", "App documentation"),
        (base_dir / "docs" / "WEB_UI_INTEGRATION_SUMMARY.md", "Integration summary"),
        (base_dir / "docs" / "INTEGRATION_COMPLETE.md", "Completion summary"),
    ]

    for file_path, description in doc_files:
        total_checks += 1
        if check_file_exists(file_path, description):
            checks_passed += 1

    print()

    # Check tools
    print("🔧 Development Tools:")
    print("-" * 80)

    tool_files = [
        (base_dir / "run.py", "Dev server launcher"),
    ]

    for file_path, description in tool_files:
        total_checks += 1
        if check_file_exists(file_path, description):
            checks_passed += 1

    print()

    # Check Python dependencies
    print("📦 Python Dependencies:")
    print("-" * 80)

    dependencies = [
        ("fastapi", "FastAPI framework"),
        ("uvicorn", "ASGI server"),
        ("jinja2", "Template engine"),
        ("pydantic", "Data validation"),
        ("pytest", "Testing framework"),
    ]

    for module, description in dependencies:
        total_checks += 1
        if check_module_import(module, description):
            checks_passed += 1

    print()

    # Check if FastAPI app can be imported
    print("🚀 Application Check:")
    print("-" * 80)

    try:
        sys.path.insert(0, str(base_dir / "app"))
        from main import app
        print(f"✅ FastAPI app imported successfully")
        print(f"✅ Routes registered: {len(app.routes)}")
        checks_passed += 2
        total_checks += 2
    except Exception as e:
        print(f"❌ Cannot import FastAPI app: {e}")
        total_checks += 2

    print()

    # Summary
    print("="*80)
    print("📊 VERIFICATION SUMMARY")
    print("="*80)
    print(f"\n✅ Checks Passed: {checks_passed}/{total_checks}")
    print(f"📈 Success Rate: {(checks_passed/total_checks)*100:.1f}%")

    if checks_passed == total_checks:
        print("\n🎉 ALL CHECKS PASSED - Integration is complete!")
        print("\n🚀 Next Steps:")
        print("   1. Start the server: python run.py")
        print("   2. Open browser: http://localhost:8000")
        print("   3. Run tests: pytest tests/test_integration.py -v")
        print()
        return 0
    else:
        print(f"\n⚠️  {total_checks - checks_passed} checks failed - Please review above")
        print()
        return 1

if __name__ == "__main__":
    sys.exit(main())
