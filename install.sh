#!/bin/bash

# Check if python is installed
PIP="pip3.10"
PYTHON="python3.10"
if ! hash python3.10; then
    PIP="pip3"
    PYTHON="python3"
    if ! hash python3; then
        PIP="pip"
        PYTHON="python"
        if ! hash python; then
            echo "python is not installed"
            exit 1
        fi
    fi
fi

# Check python version
version=$($PYTHON -V 2>&1 | grep -Po '(?<=Python )(.)(?=\..*)')
if [[ $version -lt 3 ]] 
then
    echo "Python version 3.9 required"
    exit 1
fi
version=$($PYTHON -V 2>&1 | grep -Po '(?<=Python 3\.)(.)(?=\..*)')
if [[ $version -lt 9 ]] 
then
    echo "Python version 3.9 required"
    exit 1
fi

# Install requirements
$PIP install -r requirements.txt
exit 0