import setuptools

setuptools.setup(
    name="xmldsig-client",
    description="A command-line tool for sending XML messages with digital signatures.",
    author="Kraken Technologies Limited",
    author_email="talent@octopus.energy",
    url="https://github.com/octoenergy/xmldsig-client",
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    install_requires=[
        "cryptography",
        "pyOpenSSL",
        "requests",
        "signxml",
        "xmlschema",
    ],
    entry_points={
        "console_scripts": [
            "xmldsig-client = xmldsig.__main__:main",
        ],
    },
    version_config=True,
    setup_requires=["setuptools-git-versioning"],
    classifiers=[
        "Environment :: Console",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Testing :: Traffic Generation",
        "Topic :: Text Processing :: Markup :: XML",
    ],
)
