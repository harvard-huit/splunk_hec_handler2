from setuptools import setup

setup(
    name='splunk_hec_handler',
    version='1.3.0',
    license='MIT License',
    description='A Python logging handler to sends logs to Splunk using HTTP event collector (HEC)',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='vavarachen',
    url='https://github.com/vavarachen/splunk_hec_handler',
    packages=['splunk_hec_handler'],
    python_requires='>=3.6',
    install_requires=['requests >= 2.6.0, < 3.0.0', 'requests'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: System :: Logging'
    ]
)
