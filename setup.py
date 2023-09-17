from setuptools import setup

setup(
    name="dynip-namecom",
    version="1.0.0",
    description="Dynamic IPs for domains using name.com",
    author="Dan Herbert",
    author_email="dyndns-namecom@hrbrt.co",
    license="Apache 2.0",
    py_modules=["dynip"],
    install_requires=[
        "python-dateutil==2.8.2",
        "pyyaml==6.0",
        "requests==2.31.0",
    ],
)
