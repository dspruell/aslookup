from setuptools import setup


setup(
    name='aslookup',
    version='0.20',
    description='IP-BGP query script',
    long_description='Client script for Shadowserver or Team Cymru IP-ASN lookup service over DNS',
    py_modules=['aslookup'],
    include_package_data=True,
    author='Darren Spruell',
    author_email='phatbuckett@gmail.com',
    url='https://github.com/dspruell/aslookup',
    install_requires=[
        'dnspython',
    ],
    classifiers=[
        #'Development Status :: 3 - Alpha',
        #'Development Status :: 4 - Beta',
        'Development Status :: 5 - Production/Stable',
        #'Development Status :: 6 - Mature',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python :: 3',
    ],
    entry_points={
        'console_scripts': [
            'as-lookup = aslookup:main',
        ],
    },
)
