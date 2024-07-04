from setuptools import setup
from Cython.Build import cythonize
import test_additivity2

setup(
    name='test_additivity2',
    ext_modules=cythonize("test_additivity2.pyx"),
)
