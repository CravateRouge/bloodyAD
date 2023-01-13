from setuptools import setup

from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="bloodyAD",
    version="0.2.1",
    description="AD Privesc Swiss Army Knife",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="CravateRouge",
    author_email="baptiste.crepin@ntymail.com",
    url="https://github.com/CravateRouge/bloodyAD",
    download_url=(
        "https://github.com/CravateRouge/bloodyAD/archive/refs/tags/v0.2.1.tar.gz"
    ),
    license="MIT",
    install_requires=[
        "cryptography>=37.0.2",
        "ldap3>=2.9.1",
        'gssapi>=1.8.1 ; platform_system=="Linux" or platform_system=="Darwin"',
        'winkerberos>=0.9.0; platform_system=="Windows"',
    ],
    keywords=["Active Directory", "Privilege Escalation"],
    classifiers=[
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    entry_points={"console_scripts": ["bloodyAD = bloodyAD.main:main"]},
)
