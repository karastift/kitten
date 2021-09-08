from setuptools import find_packages, setup

setup(
    name='kitten',
    version='0.1',
    url='https://github.com/karastift/kitten.git',
    author='kara',
    install_requires=['argparse'],
    scripts=['kitten/kitten'],
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
    ],
    package_dir={'': 'kitten'},
    packages=find_packages(where='kitten'),
    python_requires='>=3.6, <4',
    package_data={
        'sample': ['port_data.json'],
    },
)