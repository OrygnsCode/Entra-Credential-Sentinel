from setuptools import setup, find_packages

setup(
    name="entra_sentinel",
    version="3.0.0",
    description="Entra Credential Sentinel - Audit Azure AD Apps & Service Principals",
    author="Entra Sentinel Team",
    packages=find_packages(exclude=("tests", "tests.*")),
    install_requires=[
        "requests",
        "python-dotenv",
        "msal"
    ],
    entry_points={
        "console_scripts": [
            "entra-credential-sentinel=entra_sentinel.cli:main",
        ],
    },
    python_requires=">=3.8",
)
