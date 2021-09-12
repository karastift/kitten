from setuptools import setup, find_packages

setup(
    name='kitten',
    version='0.1',
    url='https://github.com/karastift/kitten.git',
    author='kara',
    install_requires=['argparse', 'scapy'],
    
    py_modules=['kitten'],
    entry_points={
        'console_scripts': [
            'kitten=kitten:main',
        ]
    },
    packages=find_packages(where='kitten') + ['data'],
    package_dir={'': 'kitten'},
    package_data={
        '': ['port_data.json'],
    },
    include_package_data=True,
    
    classifiers=[
        'Development Status :: 3 - Alpha',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
    ],
    python_requires='>=3.6, <4',
)