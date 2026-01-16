# setup.py

import codecs

with codecs.open('build.py', 'r') as build_file:
    build_source = build_file.read()

source = dict()

exec(build_source, source)

setup = source['setup']

def main() -> None:
    """Runs the function to distribute the package."""

    setup(
        package="sniffingio",
        exclude=[
            "__pycache__",
            "*.pyc"
        ],
        include=[],
        requirements="requirements.txt",
        dev_requirements="requirements-dev.txt",
        name='sniffing-io',
        version='0.4.0',
        description=(
            "A simple package for packet sniffing, "
            "with static/dynamic filtering options, "
            "real-time reaction, I/O operations and more."
        ),
        license='MIT',
        author="Shahaf Frank-Shapir",
        author_email='shahaffrs@gmail.com',
        url='https://github.com/Shahaf-F-S/sniffing-io',
        long_description_content_type="text/markdown",
        classifiers=[
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.12",
            "Programming Language :: Python :: 3.13",
            "Programming Language :: Python :: 3.14",
            "Operating System :: OS Independent"
        ]
    )

if __name__ == "__main__":
    main()
