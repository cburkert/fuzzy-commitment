from setuptools import (
    setup,
    find_packages,
)


def readme():
    with open('README.rst') as f:
        return f.read()


setup(
    name='fuzzy-commitment',
    version='0.1.1',
    description='A fuzzy commitment scheme originally presented by Juels and Wattenberg',
    long_description=readme(),
    author='Christian Burkert',
    url='https://github.com/cburkert/fuzzy-commitment',
    packages=find_packages(),
    install_requires=[
        'bchlib',
        'BitVector',
    ],
)
