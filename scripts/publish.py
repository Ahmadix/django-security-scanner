
#!/usr/bin/env python3
"""
Script to publish django-security-scanner to PyPI.

Usage:
    python scripts/publish.py --test    # Upload to TestPyPI
    python scripts/publish.py          # Upload to PyPI
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_command(cmd, check=True):
    """Run a shell command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=check, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description="Publish to PyPI")
    parser.add_argument(
        "--test", 
        action="store_true", 
        help="Upload to TestPyPI instead of PyPI"
    )
    parser.add_argument(
        "--skip-build", 
        action="store_true", 
        help="Skip building the package"
    )
    args = parser.parse_args()

    # Change to project root
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    print("🔒 Publishing django-security-scanner...")
    
    if not args.skip_build:
        # Clean previous builds
        print("🧹 Cleaning previous builds...")
        for path in ["dist", "build", "*.egg-info"]:
            run_command(["rm", "-rf", path], check=False)
        
        # Build the package
        print("📦 Building package...")
        run_command([sys.executable, "-m", "build"])
    
    # Upload to PyPI
    if args.test:
        print("📤 Uploading to TestPyPI...")
        run_command([
            sys.executable, "-m", "twine", "upload", 
            "--repository", "testpypi", 
            "dist/*"
        ])
        print("✅ Uploaded to TestPyPI!")
        print("🔗 Check: https://test.pypi.org/project/django-security-scanner/")
    else:
        print("📤 Uploading to PyPI...")
        run_command([sys.executable, "-m", "twine", "upload", "dist/*"])
        print("✅ Uploaded to PyPI!")
        print("🔗 Check: https://pypi.org/project/django-security-scanner/")


if __name__ == "__main__":
    main()
