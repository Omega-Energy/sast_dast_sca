from setuptools import setup

setup(
    name="trustctl",
    version="0.1.0",
    py_modules=["trustctl"],
    install_requires=[
        "typer[all]>=0.12.0",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "trustctl=trustctl:app",
        ],
    },
)
