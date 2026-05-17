from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_desc = f.read()

setup(
    name="recon47",
    version="2.0.0",
    author="Munia936",
    description="Recon47 — Automated Reconnaissance & Vulnerability Scanner",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "dnspython>=2.3.0",
        "python-whois>=0.8.0",
        "reportlab>=4.0.0",
    ],
    extras_require={
        "ai": ["anthropic>=0.20.0"],
        "full": [
            "dnspython>=2.3.0",
            "python-whois>=0.8.0",
            "reportlab>=4.0.0",
            "anthropic>=0.20.0",
        ],
    },
    entry_points={
        "console_scripts": ["recon47=recon47.main:main"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Environment :: Console",
    ],
    keywords="recon reconnaissance pentest vulnerability scanner cybersecurity automation",
)
