import io
import re

from setuptools import setup

with io.open("flask_jwt_extended/__init__.py", encoding="utf-8") as f:
    version = re.search(r"__version__ = \"(.+)\"", f.read()).group(1)


with open("README.md", "r") as f:
    long_description = f.read()


setup(
    name="Flask-JWT-Extended",
    version=version,
    url="https://github.com/vimalloc/flask-jwt-extended",
    license="MIT",
    author="Lily Acadia Gilbert",
    author_email="lily.gilbert@hey.com",
    description="Extended JWT integration with Flask",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=["flask", "jwt", "json web token"],
    packages=["flask_jwt_extended"],
    zip_safe=False,
    platforms="any",
    install_requires=[
        "Werkzeug>=0.14",  # Needed for SameSite cookie functionality
        "Flask>=2.0,<3.0",
        "PyJWT>=2.0,<3.0",
        "typing_extensions>=3.7.4; python_version<'3.8'",  # typing.Literal
    ],
    extras_require={"asymmetric_crypto": ["cryptography>=3.3.1"]},
    python_requires=">=3.6,<4",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
