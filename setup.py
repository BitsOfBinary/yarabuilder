import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="yarabuilder",
    version="0.0.2",
    author="BitsOfBinary",
    description="A package to build YARA rules using Python",
    long_description=long_description,
    test_suite="tests",
    url="https://github.com/BitsOfBinary/yarabuilder",
    packages=setuptools.find_packages(exclude=['docs', 'tests']),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)