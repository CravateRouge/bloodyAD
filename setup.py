from setuptools import setup

setup(name='bloodyAD',
      version='0.1',
      description='AD Privesc Swiss Army Knife',
      author='CravateRouge',
      author_email='baptiste.crepin@ntymail.com',
      url='https://github.com/CravateRouge/bloodyAD',
      packages=['bloodyAD'],
      license='MIT',
      install_requires=['dsinternals>=1.2.4','impacket>=0.10.0','ldap3>=2.9; python_version >= "3.6"'],
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
      scripts=['bloodyAD.py'],
      python_requires='>=3.6'
      )