from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='cmloot',
    scripts=['cmloot.py'],
    version='1.0.0',
    long_description=readme,
    author='Andreas Vikerup, Shelltrail',
    author_email='',
    url='https://github.com/shelltrail/cmloot',
    license=license,
    install_requires=requirements
)
