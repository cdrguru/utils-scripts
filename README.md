# utils-scripts

A collection of reusable utility scripts packaged for easy installation and CLI usage.

## Installation

```bash
pip install -e .
```

## Usage

```bash
delete-venvs <directory>
```

---
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'
      - name: Install dependencies
        run: |
          pip install flake8
      - name: Lint with flake8
        run: |
          flake8 src/utils_scripts

  test:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'
      - name: Install package and test dependencies
        run: |
          pip install -e .
          pip install pytest
      - name: Run tests
        run: |
          pytest
