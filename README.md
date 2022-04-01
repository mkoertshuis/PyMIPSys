# Modular Intrusion Prevention System

This program is an alternative to the popular fail2ban as an university project.

## Installation

This program only runs correctly with Python 3.9 or higher. To install the nececarry dependencies run install.sh or use pip:

```bash
pip3 install -r requirements.txt
```

### Wordpress

For this program to work for wordpres the [WP Activity Log](https://wordpress.org/plugins/wp-security-audit-log/) plugin needs to be installed and configured. By default [WP Activity Log](https://wordpress.org/plugins/wp-security-audit-log/) only logs the first 10 attempts. You can change this setting in the "Enable/Disable Events" tab of WP Activity Log.

## Usage

To run the program it needs access to the sql database. You can parse the username and password as follows:

```bash
python3 PyMIPSys.py -u <username> -p <password>
```

## Configuration

The program is configurable with ban_settings.ini. Make sure this file is in the same folder as PyMIPSys.py. Here you can enable and disable all the modules separately.
