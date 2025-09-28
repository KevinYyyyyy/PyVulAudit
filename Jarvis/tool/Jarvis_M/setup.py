from setuptools import setup, find_packages

setup(
    name="jarvis-cli",
    version="0.1.0",
    description="A call graph generation tool",
    author="Your Name",
    author_email="you@example.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "jarvis-cli=Jarvis.jarvis_cli:main",
        ],
    },
    install_requires=[
        # Add dependencies here if needed, e.g.:
        # "requests",
    ],
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)