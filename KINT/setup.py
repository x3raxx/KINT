from setuptools import setup, find_packages

setup(
    name='kint',
    version='0.9',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'kint=kint.cli:main'
        ]
    },
    install_requires=[
        'requests',
        'rich',
        'beautifulsoup4'
    ],
    include_package_data=True,
)
