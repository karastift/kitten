from setuptools import setup

setup(
    name='kitten',
    version='0.1',
    url='https://github.com/karastift/kitten.git',
    author='kara',
    install_requires=['argparse', 'scapy', 'termcolor'],
    
    py_modules=['kitten'],
    entry_points={
        'console_scripts': [
            'kitten=kitten:main',
        ]
    },
    packages=['paws'],
    package_data={
        'sample': ['port_data.json'],
    },
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