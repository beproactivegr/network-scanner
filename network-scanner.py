#!/usr/bin/env python3

"""
Network Scanner

Copyright (c) 2023 @beproactivegr
https://github.com/beproactivegr/network-scanner

A free and open source utility for network discovery.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

For more see the file 'LICENSE' for copying permission.
"""

__author__ = "beproactivegr"
__copyright__ = "Copyright (c) 2023 @beproactivegr"
__credits__ = ["beproactivegr"]
__license__ = "GPLv3"
__version__ = "1.0"
__maintainer__ = "beproactivegr"

################################

import subprocess

try:
	from termcolor import colored
except ImportError:
	subprocess.call(['pip', 'install', 'termcolor'])

try:
	from termcolor import colored
except ImportError:
	sys.exit()

################################

def is_platform_windows():
    return platform.system() == "Windows"

def is_platform_linux():
    return platform.system() == "Linux"


def CheckPythonNmapInstallation():
	try:
		print(colored("Checking Python Nmap library: ", "white"), end="")
		import nmap
		print(colored("Python Nmap library is installed.", "green"))
	except ImportError:
		print(colored('Python-nmap library is not installed. Installing now...', 'yellow'))
		subprocess.call(['pip', 'install', 'python-nmap'])

	try:
		import nmap
	except ImportError:
		print(colored('Python-nmap library is not installed. Exiting...', 'red'))
		sys.exit()


def CheckNmapInstallation():
	try:
		print(colored("Checking Nmap: ", "white"), end="")
		subprocess.check_output(["nmap", "--version"])
		print(colored("Nmap is installed.", "green"))
	except OSError:
		print(colored("Nmap is not installed.", "yellow"))

		if is_platform_linux():
			print(colored("Installing it now...", "yellow"))
			subprocess.call(["apt", "update"])
			subprocess.call(["apt", "install", "-y", "nmap"])

if __name__ == '__main__':

	try:

		print()
		print(colored("Network Scanner - https://beproactive.gr", "cyan"))
		print(colored("A free and open source utility for network discovery.", "cyan"))
		print()

		CheckNmapInstallation()
		CheckPythonNmapInstallation()

		print()
	except KeyboardInterrupt:
		sys.exit(0)
