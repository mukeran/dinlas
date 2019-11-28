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
├── dinlas.py - Program Entry
├── lib
│   ├── core - Core Classes
│   │   ├── ArgumentParser.py - Command line parser
│   │   ├── Controller.py - Main controller
│   │   ├── __init__.py
│   │   ├── Logger.py - Console logger
│   │   ├── ModuleLoader.py - Module loader
│   │   └── Reporter.py - Reporter generator
│   ├── extensions - Scan extensions
│   │   ├── ArgumentParser.py - Command line parser
│   │   ├── Controller.py - Main controller
│   │   ├── __init__.py
│   │   ├── Logger.py - Console logger
│   │   ├── ModuleLoader.py - Module loader
│   │   └── Reporter.py - Reporter generator
│   └── utils - Program utils or common modules
│       ├── __init__.py
│       ├── DirectorySeacher.py - 
│       ├── ModuleLoader.py - Module loader
│       ├── ModuleLoader.py - Module loader
│       └── Reporter.py - Reporter generator
├── README.md
└── requirements.txt
```
