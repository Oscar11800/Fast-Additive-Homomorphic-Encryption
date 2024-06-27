import os

def check_imports(path):
    libraries = [
        "aiohttp", "aiosignal", "alpaca-trade-api", "appdirs", "astroid", "asttokens",
        "async-timeout", "attrs", "beautifulsoup4", "black", "blankly", "blinker",
        "bokeh", "certifi", "chardet", "charset-normalizer", "click", "colorama",
        "command-not-found", "contourpy", "cryptography", "cycler", "dateparser",
        "dbus-python", "decorator", "deprecation", "dill", "distro", "distro-info",
        "exceptiongroup", "executing", "filelock", "flake8", "fonttools", "frozendict",
        "frozenlist", "gitdb", "GitPython", "html5lib", "httplib2", "idna",
        "importlib-metadata", "iniconfig", "ipython", "isort", "jedi", "jeepney",
        "Jinja2", "keyring", "kiwisolver", "launchpadlib", "lazr.restfulclient",
        "lazr.uri", "lxml", "MarkupSafe", "matplotlib", "matplotlib-inline", "mccabe",
        "merkletools", "meson", "more-itertools", "mplfinance", "msgpack", "multidict",
        "multitasking", "mypy", "mypy-extensions", "netifaces", "newnewtulipy", "numpy",
        "oauthlib", "packaging", "pandas", "parso", "pathspec", "peewee", "pexpect",
        "pillow", "platformdirs", "plotly", "pluggy", "prompt-toolkit", "psaw", "psutil",
        "ptyprocess", "pure-eval", "pyarrow", "pycodestyle", "pycryptodome", "pyflakes",
        "pygame", "Pygments", "PyGObject", "PyJWT", "pylint", "pyparsing", "pysha3",
        "pytest", "pytest-json-report", "pytest-metadata", "pytest-mypy", "pytest-timeout",
        "python-apt", "python-binance", "python-dateutil", "pytz", "PyYAML", "questionary",
        "regex", "requests", "scipy", "SecretStorage", "six", "smmap", "soupsieve", "stack-data",
        "systemd-python", "tenacity", "termcolor", "tomli", "tomlkit", "tornado", "traitlets",
        "typed-ast", "typing_extensions", "tzdata", "tzlocal", "ubuntu-advantage-tools", "ufw",
        "ujson", "unattended-upgrades", "urllib3", "wadllib", "wcwidth", "webencodings",
        "websocket-client", "websockets", "XlsxWriter", "xyzservices", "yaspin", "yfinance", "zipp"
    ]

    # Dictionary to track libraries found
    found_libraries = {lib: [] for lib in libraries}

    # Traverse the directory and subdirectories
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith('.py'):  # Check only Python files
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    contents = f.read()
                    for lib in libraries:
                        if f"import {lib}" in contents or f"from {lib} import" in contents:
                            found_libraries[lib].append(file_path)

    # Print out the results
    for lib, files in found_libraries.items():
        if files:
            print(f"{lib} is imported in:")
            for file in files:
                print(f"  - {file}")
            print("")

# Change parameter to your root foler
check_imports('/mnt/c/Desktop/Programming/Fast-Additive-Homomorphic-Encryption')