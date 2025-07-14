
"""Setup configuration for django-security-scanner package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="django-security-scanner",
    version="1.0.0",
    author="Django Security Scanner Team",
    author_email="security@django-scanner.org",
    description="Professional security audit tool for Django projects",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/django-security-scanner/django-security-scanner",
    packages=find_packages(exclude=["tests*"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.0",
        "Framework :: Django :: 4.1",
        "Framework :: Django :: 4.2",
        "Framework :: Django :: 5.0",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Django>=3.2",
    ],
    entry_points={
        "console_scripts": [
            "django-security-scan=django_security_scanner.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
