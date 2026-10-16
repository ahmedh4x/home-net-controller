# Configuration & Setup Guide

## System Prerequisites
- **Controller Workstation:** Windows 10/11, Linux, or macOS with Python 3.10+.
- **Gateway Router:** OpenWrt 22.03+, Generic Linux Gateway, or MikroTik RouterOS 7.1+.

## Installation
```sh
pip install -r requirements.txt
```

## Running the Desktop GUI
To launch the full graphical interface:
```cmd
scripts\run_app.bat
```
or
```sh
python main.py
```

## Running via CLI
To list discovered devices:
```sh
python main.py devices --refresh
```
To block a device:
```sh
python main.py block <MAC_OR_GUID>
```
To set bandwidth shaping:
```sh
python main.py limit <MAC_OR_GUID> --download 10240 --upload 2048
```
To run full gateway diagnostics:
```sh
python main.py diagnostics
```
To run reconciliation pass:
```sh
python main.py reconcile
```
