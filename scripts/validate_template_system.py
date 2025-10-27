#!/usr/bin/env python3
"""
Template System Validation Script

Validates that all template system files are in place and properly configured.
Run this after integration to ensure everything is working correctly.
"""

import os
import json
import sys
from pathlib import Path
import logging

# Setup logging
logger = logging.getLogger(__name__)


# Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def check_file_exists(filepath, description):
    """Check if a file exists and print status"""
    if os.path.exists(filepath):
        logger.info(f"  {GREEN}✓{RESET} {description}")
        return True
    else:
        logger.error(f"  {RED}✗{RESET} {description}")
        logger.info(f"    {YELLOW}Missing: {filepath}{RESET}")
        return False

def check_file_contains(filepath, search_string, description):
    """Check if file contains a specific string"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if search_string in content:
                logger.info(f"  {GREEN}✓{RESET} {description}")
                return True
            else:
                logger.error(f"  {RED}✗{RESET} {description}")
                logger.info(f"    {YELLOW}Not found: {search_string}{RESET}")
                return False
    except Exception as e:
        logger.error(f"  {RED}✗{RESET} {description}")
        logger.error(f"    {YELLOW}Error: {e}{RESET}")
        return False

def validate_template_system():
    """Main validation function"""
    logger.info(f"\n{BLUE}{'='*60}{RESET}")
    logger.info(f"{BLUE}Template System Validation{RESET}")
    logger.info(f"{BLUE}{'='*60}{RESET}\n")

    # Determine project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    app_dir = project_root / "app"

    all_checks_passed = True

    # 1. Core JavaScript Files
    logger.info(f"{BLUE}1. Core JavaScript Files{RESET}")
    checks = [
        (app_dir / "static/js/template-manager.js", "Template Manager Class"),
        (app_dir / "static/js/create-with-templates.js", "Alpine.js Integration")
    ]
    for filepath, desc in checks:
        if not check_file_exists(filepath, desc):
            all_checks_passed = False
    logger.info()

    # 2. UI Components
    logger.info(f"{BLUE}2. UI Components (Modals){RESET}")
    checks = [
        (app_dir / "templates/components/save-template-modal.html", "Save Template Modal"),
        (app_dir / "templates/components/template-manager-modal.html", "Template Manager Modal")
    ]
    for filepath, desc in checks:
        if not check_file_exists(filepath, desc):
            all_checks_passed = False
    logger.info()

    # 3. Backend Updates
    logger.info(f"{BLUE}3. Backend Implementation{RESET}")
    main_py = app_dir / "main.py"
    checks = [
        (main_py, "class TemplateModel", "TemplateModel defined"),
        (main_py, "POST /api/templates/save", "POST /api/templates/save endpoint"),
        (main_py, "GET /api/templates/list", "GET /api/templates/list endpoint"),
        (main_py, "DELETE /api/templates/", "DELETE /api/templates/{id} endpoint"),
        (main_py, '"templates": True', "Templates feature flag in health check")
    ]
    for filepath, search_str, desc in checks:
        if not check_file_contains(filepath, search_str, desc):
            all_checks_passed = False
    logger.info()

    # 4. Documentation Files
    logger.info(f"{BLUE}4. Documentation Files{RESET}")
    checks = [
        (project_root / "docs/TEMPLATE_SYSTEM.md", "System Documentation"),
        (project_root / "docs/TEMPLATE_QUICK_REFERENCE.md", "Quick Reference Guide"),
        (project_root / "docs/agents/AGENT_9_TEMPLATE_IMPLEMENTATION_SUMMARY.md", "Implementation Summary"),
        (project_root / "docs/agents/TEMPLATE_INTEGRATION_GUIDE.md", "Integration Guide"),
        (project_root / "TEMPLATE_SYSTEM_DELIVERY.md", "Delivery Package")
    ]
    for filepath, desc in checks:
        if not check_file_exists(filepath, desc):
            all_checks_passed = False
    logger.info()

    # 5. Integration Checks (create.html)
    logger.info(f"{BLUE}5. Integration Status (create.html){RESET}")
    create_html = app_dir / "templates/create.html"
    if os.path.exists(create_html):
        checks = [
            ("videoCreatorWithTemplates()", "Alpine component uses videoCreatorWithTemplates"),
            ("showSaveTemplateModal", "Save Template modal state variable"),
            ("My Templates", "My Templates section present"),
            ("save-template-modal.html", "Save Template modal included"),
            ("template-manager-modal.html", "Template Manager modal included")
        ]
        integration_complete = True
        for search_str, desc in checks:
            if not check_file_contains(create_html, search_str, desc):
                integration_complete = False
                all_checks_passed = False

        if integration_complete:
            logger.info(f"\n  {GREEN}✓ Integration appears complete!{RESET}")
        else:
            logger.warning(f"\n  {YELLOW}⚠ Integration incomplete. See: docs/agents/TEMPLATE_INTEGRATION_GUIDE.md{RESET}")
    else:
        logger.error(f"  {RED}✗ create.html not found{RESET}")
        all_checks_passed = False
    logger.info()

    # 6. Optional: Base Template Check
    logger.info(f"{BLUE}6. Base Template (Optional){RESET}")
    base_html = app_dir / "templates/base.html"
    if os.path.exists(base_html):
        checks = [
            ("template-manager.js", "Template Manager script loaded"),
            ("create-with-templates.js", "Template integration script loaded")
        ]
        for search_str, desc in checks:
            check_file_contains(base_html, search_str, desc)
    else:
        logger.info(f"  {YELLOW}ℹ base.html not found (scripts may be loaded elsewhere){RESET}")
    logger.info()

    # 7. JavaScript Validation (if Node.js available)
    logger.info(f"{BLUE}7. JavaScript Syntax Validation{RESET}")
    try:
        import subprocess
        # Check if node is available
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"  {GREEN}✓{RESET} Node.js available: {result.stdout.strip()}")

            # Validate template-manager.js
            template_manager = app_dir / "static/js/template-manager.js"
            result = subprocess.run(['node', '-c', str(template_manager)], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"  {GREEN}✓{RESET} template-manager.js syntax valid")
            else:
                logger.error(f"  {RED}✗{RESET} template-manager.js syntax error:")
                logger.info(f"    {result.stderr}")
                all_checks_passed = False

            # Validate create-with-templates.js
            create_templates = app_dir / "static/js/create-with-templates.js"
            result = subprocess.run(['node', '-c', str(create_templates)], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"  {GREEN}✓{RESET} create-with-templates.js syntax valid")
            else:
                logger.error(f"  {RED}✗{RESET} create-with-templates.js syntax error:")
                logger.info(f"    {result.stderr}")
                all_checks_passed = False
        else:
            logger.info(f"  {YELLOW}ℹ Node.js not available, skipping JS validation{RESET}")
    except FileNotFoundError:
        logger.info(f"  {YELLOW}ℹ Node.js not installed, skipping JS validation{RESET}")
    logger.info()

    # Final Summary
    logger.info(f"{BLUE}{'='*60}{RESET}")
    if all_checks_passed:
        logger.info(f"{GREEN}✓ All checks passed! Template system is ready.{RESET}")
        logger.info(f"\n{BLUE}Next Steps:{RESET}")
        logger.info(f"  1. If integration incomplete, see: docs/agents/TEMPLATE_INTEGRATION_GUIDE.md")
        logger.info(f"  2. Start the web server: python app/main.py")
        logger.info(f"  3. Test at: http://localhost:8000/create")
        logger.info(f"  4. User guide: docs/TEMPLATE_QUICK_REFERENCE.md")
        return 0
    else:
        logger.error(f"{RED}✗ Some checks failed. Review the output above.{RESET}")
        logger.info(f"\n{BLUE}Resources:{RESET}")
        logger.info(f"  • Integration Guide: docs/agents/TEMPLATE_INTEGRATION_GUIDE.md")
        logger.info(f"  • Implementation Summary: docs/agents/AGENT_9_TEMPLATE_IMPLEMENTATION_SUMMARY.md")
        logger.info(f"  • Delivery Package: TEMPLATE_SYSTEM_DELIVERY.md")
        return 1

if __name__ == "__main__":
    try:
        exit_code = validate_template_system()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info(f"\n\n{YELLOW}Validation interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n{RED}Validation error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
