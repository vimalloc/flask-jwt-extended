"""
Flask-JWT-Extended
------------------
Flask-Login provides jwt endpoint protection for Flask.
"""
import io
import re
from setuptools import setup

with io.open('flask_jwt_extended/__init__.py', encoding='utf-8') as f:
    version = re.search(r"__version__ = '(.+)'", f.read()).group(1)


with open("README.md", "r") as f:
    long_description = f.read()


setup(name='Flask-JWT-Extended',
      version=version,
      url='https://github.com/vimalloc/flask-jwt-extended',
      license='MIT',
      author='Landon Gilbert-Bland',
      author_email='landogbland@gmail.com',
      description='Extended JWT integration with Flask',
      long_description=long_description,
      long_description_content_type="text/markdown",
      keywords=['flask', 'jwt', 'json web token'],
      packages=['flask_jwt_extended'],
      zip_safe=False,
      platforms='any',
      install_requires=[
          'Werkzeug>=0.14',  # Needed for SameSite cookie functionality
          'Flask',
          'PyJWT',
      ],
      extras_require={
        'asymmetric_crypto':  ["cryptography >= 2.3"]
      },
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
      ])
