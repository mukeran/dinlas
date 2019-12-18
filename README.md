# Dinlas - A web scanner

Dinlas is a web scanner which can help developers find security vulnerabilities in their programs.  
But you have to pay attention that this is a project for a course.

## Main Developers

[mukeran](https://github.com/mukeran) Personal Blog: https://blogs.mukeran.com 
[am009](https://github.com/am009) 
[Tinywangxx](https://github.com/tinywangxx)

## Project Layout

```
.
├── dictionary
│   ├── blind_sql_Payloads.txt
│   ├── common_directory.txt
│   ├── file_upload_payloads
│   │   ├── basic.jsp
│   │   ├── phpinfo.gif
│   │   ├── phpinfo.jpg
│   │   └── phpinfo.php
│   ├── weak_password.txt
│   └── weak_username.txt
├── lib
│   ├── __init__.py
│   ├── core
│   │   ├── __init__.py
│   │   ├── ArgumentParser.py
│   │   ├── Controller.py
│   │   ├── Dictionary.py
│   │   └── Reporter.py
│   ├── exceptions.py
│   ├── extensions
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── default.py
│   │   ├── dynamic.py
│   │   └── static.py
│   ├── modules
│   │   ├── __init__.py
│   │   ├── CSRFDetector.py
│   │   ├── DirectorySearcher.py
│   │   ├── DynamicRequestFinder.py
│   │   ├── FileUploadDetector.py
│   │   ├── ReflectedXSSDetector.py
│   │   ├── SQLInjector.py
│   │   ├── SQLMapInjector
│   │   ├── SSTIDetector.py
│   │   ├── StaticRequestFinder.py
│   │   ├── StoredXSSDetector.py
│   │   └── WeakPasswordTester.py
│   └── utils
│       ├── __init__.py
│       └── random.py
├── templates
│   └── default.jinja2
├── dinlas.py - Main entry
├── requirements.txt
└── README.md
```

## Installation and First Run

When you finished downloading the [release](), you have to do some preparations below:

1. Install Python 3.8 and pip 19 or above;
2. Run `pip install -r requestments.txt`;
3. Download Google Chrome and its [Chrome Driver](https://chromedriver.chromium.org/);
4. Download [browsermob-proxy](https://github.com/lightbody/browsermob-proxy);
5. Extract browsermob-proxy and Chrome Driver into a PATH path.

Now you can run ./dinlas.py static \<your_url\>.

