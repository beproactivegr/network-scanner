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

import os
import sys
import subprocess
import ipaddress
import re
from threading import Thread

try:
	from termcolor import colored
except ImportError:
	print('termcolor library is not installed. Installing now...')
	subprocess.call(['pip', 'install', 'termcolor'])

try:
	from termcolor import colored
except ImportError:
	sys.exit()

################################

def PrintColored(message, color):
	print(colored(message, color), end="")


def PrintFlushColored(message, color):
	print(colored(message, color), end="", flush=True)


def PrintLineColored(message, color):
	print(colored(message, color))


try:
	import nmap
except ImportError:
	PrintLineColored('Python-nmap library is not installed. Installing now...', 'yellow')
	subprocess.call(['pip', 'install', 'python-nmap'])

try:
	import nmap
except ImportError:
	PrintLineColored('Python-nmap library is not installed. Exiting...', 'red')
	sys.exit()


def IsTopPortsRangeScan(port):
	if port.count("top-") == 1:
		pattern = re.compile("^top-\d+$")
		if pattern.match(port):
			return True
	return False


def TranslatePortGroupToPortRange(port):
	if port == 'all':
		return '1-65535'
	elif port.count("top-") == 1:
		pattern = re.compile("^top-\d+$")
		if pattern.match(port):
			return port.replace("top-", "")


def isValidPortGroup(port):
	if port == 'all':
		return True
	elif port.count("top-") == 1:
		pattern = re.compile("^top-\d+$")
		if pattern.match(port):
			return True


def ScanHost(host, ports, destination):
	try:
		isTopScan = False

		tcpDestination = os.path.join(destination, f'network_scanner_tcp_results_{host}')
		gnmapFile = tcpDestination + '.gnmap'
		nmapFile = tcpDestination + '.nmap'
		xmlFile = tcpDestination + '.xml'
		csvFile = tcpDestination + '.csv'

		scanner = nmap.PortScanner()

		if IsTopPortsRangeScan(ports):
			isTopScan = True

		if isValidPortGroup(ports):
			ports = TranslatePortGroupToPortRange(ports)
		

		if isTopScan:
			scanner.scan(host, arguments=f'-sS -Pn -n -T4 --open --defeat-rst-ratelimit --top-ports {ports} --reason -oG "{gnmapFile}" -oN "{nmapFile}"')
		else:
			scanner.scan(host, arguments=f'-sS -Pn -n -T4 --open --defeat-rst-ratelimit -p{ports} --reason -oG "{gnmapFile}" -oN "{nmapFile}"')

		with open(f'{xmlFile}', 'w') as f:
			f.write(scanner.get_nmap_last_output().decode('UTF-8'))

		with open(f'{csvFile}', 'w') as f:
			f.write(scanner.csv())

		print()

		proto_width = 8
		port_width = 7
		state_width = 6
		service_width = 25

		print()
		PrintLineColored("{:<{proto_width}}  {:<{port_width}}  {:<{state_width}}  {:<{service_width}}".format("PROTOCOL", "PORT", "STATE", "SERVICE", 
			proto_width=proto_width, port_width=port_width, state_width=state_width, service_width=service_width), "white")

		for host in scanner.all_hosts():
			if scanner[host].state() == 'up':
				for proto in scanner[host].all_protocols():
					lport = scanner[host][proto].keys()
					for port in lport:
						if scanner[host][proto][port]['state'] == 'open':
							protocol = proto.upper()
							service = scanner[host][proto][port]["name"]
							PrintLineColored("{:<{proto_width}}  {:<{port_width}}  {:<{state_width}}  {:<{service_width}}".format(protocol, port, "OPEN", service, 
								proto_width=proto_width, port_width=port_width, state_width=state_width, service_width=service_width), "green")

	except Exception as e:
		#PrintLineColored(e, "red")
		return


def isValidPort(port):
	try:
	    port = int(port)
	except ValueError:
	    return False
	if port < 1 or port > 65535:
	    return False
	return True


def isValidPortRange(port):
	if port.count("-") == 1:
		ports = port.split('-')
		for port in ports:
			if not isValidPort(port):
				return False
		return True


def isValidCommaSepPorts(port):
	if port.count(",") >= 1:
		ports = port.split(',')
		for port in ports:
			if not isValidPort(port):
				return False
		return True


def IsValidPort(port):
	if not isValidPort(port) and not isValidPortRange(port) and not isValidCommaSepPorts(port) and not isValidPortGroup(port):
		return False
	return True


def IsValidHostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def IsValidIPaddress(address):
	try:
		ip = ipaddress.ip_address(address)
		return True
	except ValueError:
		return False


def is_platform_windows():
    return platform.system() == "Windows"


def is_platform_linux():
    return platform.system() == "Linux"


def CheckNmapInstallation():
	try:
		PrintColored("Checking Nmap: ", "white")
		subprocess.check_output(["nmap", "--version"])
		PrintLineColored("Nmap is installed.", "green")
	except OSError:
		PrintLineColored("Nmap is not installed (https://nmap.org/download).", "yellow")

		if is_platform_linux():
			PrintLineColored("Installing it now...", "yellow")
			subprocess.call(["apt", "update"])
			subprocess.call(["apt", "install", "-y", "nmap"])


def GetUserInput(prompt):
	return input(colored(prompt, "magenta")).lower()


def CreateDir(folder):
	if not os.path.exists(folder):
		os.makedirs(folder)

if __name__ == '__main__':

	try:

		print()
		PrintLineColored(f'Network Scanner v{__version__} - https://beproactive.gr', "cyan")
		PrintLineColored("A free and open source utility for network discovery by BeProactive.", "cyan")
		print()

		CheckNmapInstallation()
		print()


		target = GetUserInput("Please provide an IP address or a hostname to scan: ")

		while not IsValidIPaddress(target) and not IsValidHostname(target):
			PrintLineColored("Please provide a valid hostname, IP4 or IP6 address.", "yellow")
			target = GetUserInput("Please provide an IP address or a hostname to scan: ")


		ports = GetUserInput("Please provide port ranges. Ex: 22; 1-65535; 80,443,8080; all; top-100: ")

		while not IsValidPort(ports):
			PrintLineColored("Please provide valid port rages.", "yellow")
			ports = GetUserInput("Please provide port ranges. Ex: 22; 1-65535; 80,443,8080; all; top-100: ")


		print()

		PrintLineColored(f'Scanning ports {ports} on host {target}.\nThis may take a while...', "cyan")
		print()

		CreateDir('logs')
		destination = os.path.join(os.getcwd(), 'logs')

		scan_thread = Thread(target=ScanHost, args=(target, ports, destination,))
		scan_thread.start()

		while True:
			scan_thread.join(timeout=3)
			if not scan_thread.is_alive():
				break
			PrintFlushColored("..", "green")

		print()

	except KeyboardInterrupt:
		sys.exit(0)
