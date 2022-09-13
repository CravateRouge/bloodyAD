from setuptools import setup

from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(name='bloodyAD',
      version='0.1.4',
      description='AD Privesc Swiss Army Knife',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='CravateRouge',
      author_email='baptiste.crepin@ntymail.com',
      url='https://github.com/CravateRouge/bloodyAD',
      download_url='https://github.com/CravateRouge/bloodyAD/archive/refs/tags/v0.1.4.tar.gz',
      packages=['bloodyAD'],
      license='MIT',
      install_requires=['dsinternals>=1.2.4','impacket>=0.10.0','ldap3>=2.9.1; python_version >= "3.6"'],
      keywords = ['Active Directory', 'Privilege Escalation'],
      classifiers=[
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10'
      ],
      python_requires='>=3.6',
      entry_points={
        "console_scripts":["bloodyAD = bloodyAD.main:main"]
      }
)