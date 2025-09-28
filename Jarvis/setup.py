from setuptools import setup, find_packages

setup(
    name='Jarvis',
    version='0.1.0',
    description='A tool to generate CG for py projects.',
    author='Kevin Y (modified)',
    package_dir={'jarvis': 'tool/Jarvis'},
    install_requires=[
        # 如果 processing 有依赖项也可以加在这里
    ],
    include_package_data=True,
)