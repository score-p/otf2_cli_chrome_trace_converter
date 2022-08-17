#!/usr/bin/env bash

files=( $( git ls-files '*.py' | sort -u ) )

pylint "${files[@]}"
black -q --line-length 120 --skip-string-normalization "${files[@]}"
flake8 "${files[@]}"
pytype "${files[@]}"
mypy "${files[@]}"
