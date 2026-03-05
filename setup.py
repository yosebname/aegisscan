"""
Setup configuration for AegisScan package.

Defines installation requirements and entry points.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from __init__.py
init_file = Path(__file__).parent / "aegisscan" / "__init__.py"
version = None
for line in init_file.read_text().split('\n'):
    if line.startswith('__version__'):
        version = line.split('=')[1].strip().strip('"\'')
        break

if not version:
    raise RuntimeError("Unable to determine version")

# Read long description from README if it exists
long_description = ""
readme_file = Path(__file__).parent / "README.md"
if readme_file.exists():
    long_description = readme_file.read_text()

setup(
    name="aegisscan",
    version=version,
    author="AegisScan Team",
    author_email="team@aegisscan.io",
    description="Professional Network Security Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aegisscan/aegisscan",
    project_urls={
        "Bug Tracker": "https://github.com/aegisscan/aegisscan/issues",
        "Documentation": "https://docs.aegisscan.io",
        "Source Code": "https://github.com/aegisscan/aegisscan",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: Other/Proprietary License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.9",
    install_requires=[
        "sqlalchemy>=2.0.0,<3.0.0",
        "jinja2>=3.1.0,<4.0.0",
        "aiohttp>=3.8.0,<4.0.0",
    ],
    extras_require={
        "full": [
            "scapy>=2.5.0,<3.0.0",
            "weasyprint>=59.0,<60.0",
            "pyyaml>=6.0,<7.0",
            "shodan>=1.28.0,<2.0.0",
            "censys>=1.7.0,<2.0.0",
        ],
        "web": [
            "fastapi>=0.104.0,<1.0.0",
            "uvicorn>=0.24.0,<1.0.0",
            "pydantic>=2.0.0,<3.0.0",
        ],
        "dev": [
            "pytest>=7.0.0,<8.0.0",
            "pytest-asyncio>=0.21.0,<1.0.0",
            "pytest-cov>=4.0.0,<5.0.0",
            "black>=23.0.0,<24.0.0",
            "flake8>=6.0.0,<7.0.0",
            "mypy>=1.0.0,<2.0.0",
            "isort>=5.12.0,<6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "aegisscan=aegisscan.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
