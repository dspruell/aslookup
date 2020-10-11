import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='aslookup',
    version='1.0.9',
    description='IP to AS routing data query script',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    include_package_data=True,
    author='Darren Spruell',
    author_email='phatbuckett@gmail.com',
    url='https://github.com/dspruell/aslookup',
    install_requires=[
        'dnspython',
        'pytricia',
    ],
    classifiers=[
        # 'Development Status :: 3 - Alpha',
        'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python :: 3',
    ],
    entry_points={
        'console_scripts': [
            'as-lookup = aslookup.cli:main',
        ],
    },
)
