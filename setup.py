"""Setup script — pip install -e . için."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="siber-savascilar",
    version="1.0.0",
    author="Siber Savaşçılar Ekibi",
    description="OWASP Top 10 referanslı sızma testi otomasyon aracı",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    package_data={
        "siber_savascilar.reporting": ["fonts/*.ttf"],
    },
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "flask>=3.0.0",
        "pyyaml>=6.0",
        "urllib3>=2.0.0",
        "reportlab>=4.0.0",
    ],
    extras_require={
        "full": ["python-nmap>=0.7.1"],
        "dev": ["pytest>=8.0.0"],
    },
    entry_points={
        "console_scripts": [
            "siber-savascilar=siber_savascilar.cli:main",
            "siber-savascilar-web=siber_savascilar.api.server:run",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Operating System :: OS Independent",
    ],
)
