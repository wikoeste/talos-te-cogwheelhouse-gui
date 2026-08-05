from setuptools import setup

setup(
    name='te-talos-casemgr',
    version='0.0.2',
    packages=["liono", "liono.common","liono.logging","liono.pigreplay","liono.static","liono.templates"],
    description='Master Ticketing Interface',
    author='Will Koester',
    author_email='wikoeste@cisco.com',
    url='',
    entry_points={
        'console_scripts':[
            'te-talos-casemgr=',
            ],
        },
)
