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
import ctypes
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

try:
	is_admin = os.getuid() == 0
except AttributeError:
	is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

if not is_admin:
    print(colored("This script requires admin privileges to run TCP SYN scans otherwise TCP Connect will be used.", "yellow"))


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


def IsValidProto(proto):
	if proto == 'tcp':
		return True
	elif proto == 'udp':
		return True
	return False


def isValidPortGroup(port):
	if port == 'all':
		return True
	elif port.count("top-") == 1:
		pattern = re.compile("^top-\d+$")
		if pattern.match(port):
			return True


def ScanHost(scanner, host, proto, ports, destination):
	try:
		isTopScan = False
		scanFlag = '-sS'
		defeat = '--defeat-rst-ratelimit'

		hostInFilename = host.replace("/", "_")
		tcpDestination = os.path.join(destination, f'network_scanner_{proto}_results_{hostInFilename}_{ports}')
		gnmapFile = tcpDestination + '.gnmap'
		nmapFile = tcpDestination + '.nmap'
		xmlFile = tcpDestination + '.xml'
		csvFile = tcpDestination + '.csv'

		if IsTopPortsRangeScan(ports):
			isTopScan = True

		if isValidPortGroup(ports):
			ports = TranslatePortGroupToPortRange(ports)
		
		if host.count(",") >= 1:
			host = host.replace(",", " ")

		if proto == 'udp':
			scanFlag = '-sU'
			defeat = '--defeat-icmp-ratelimit'

		if isTopScan:
			scanner.scan(host, arguments=f'{scanFlag} -Pn -n -T4 --open {defeat} --top-ports {ports} --reason -oG "{gnmapFile}" -oN "{nmapFile}"')
		else:
			scanner.scan(host, arguments=f'{scanFlag} -Pn -n -T4 --open {defeat} -p{ports} --reason -oG "{gnmapFile}" -oN "{nmapFile}"')

		with open(f'{xmlFile}', 'w') as f:
			f.write(scanner.get_nmap_last_output().decode('UTF-8'))

		with open(f'{csvFile}', 'w') as f:
			f.write(scanner.csv())

		print()

		host_width = 20
		proto_width = 9
		port_width = 7
		state_width = 6
		service_width = 15
		hostname_width = 15

		print()
		PrintLineColored("{:<{host_width}} {:<{hostname_width}} {:<{proto_width}} {:<{port_width}} {:<{state_width}} {:<{service_width}}".format("IP", "HOSTNAME", "PROTOCOL", "PORT", "STATE", "SERVICE", 
			host_width=host_width, proto_width=proto_width, port_width=port_width, state_width=state_width, service_width=service_width, hostname_width=hostname_width), "white")

		for host in scanner.all_hosts():
			if scanner[host].state() == 'up':
				for proto in scanner[host].all_protocols():
					lport = scanner[host][proto].keys()
					for port in lport:
						if scanner[host][proto][port]['state'] == 'open':
							protocol = proto.upper()
							#print(scanner[host][proto][port]['product'])
							#print(scanner[host][proto][port]['version'])
							service = scanner[host][proto][port]["name"]
							PrintLineColored("{:<{host_width}} {:<{hostname_width}} {:<{proto_width}} {:<{port_width}} {:<{state_width}} {:<{service_width}}".format(host, scanner[host].hostname(), protocol, port, "OPEN", service, 
								host_width=host_width, proto_width=proto_width, port_width=port_width, state_width=state_width, service_width=service_width, hostname_width=hostname_width), "green")

	except Exception as e:
		#PrintLineColored(e, "red")
		return


def ScanHostServices(scanner, proto, destination):
	try:
		scanFlag = '-sS'
		defeat = '--defeat-rst-ratelimit'

		hosts = ' '.join(scanner.all_hosts())

		unique_ports = []
		for host in scanner.all_hosts():
			if scanner[host].state() == 'up':
				for proto in scanner[host].all_protocols():
					lport = scanner[host][proto].keys()
					for port in lport:
						if str(port) not in unique_ports:
							unique_ports.append(str(port))

		ports = ','.join(unique_ports)

		hostInFilename = hosts.replace(" ", ",")
		tcpDestination = os.path.join(destination, f'network_scanner_{proto}_services_results_{hostInFilename}_{ports}')
		gnmapFile = tcpDestination + '.gnmap'
		nmapFile = tcpDestination + '.nmap'
		xmlFile = tcpDestination + '.xml'
		csvFile = tcpDestination + '.csv'

		if proto == 'udp':
			scanFlag = '-sU'
			defeat = '--defeat-icmp-ratelimit'

		scanner.scan(hosts, arguments=f'{scanFlag} -sV -Pn -n -T4 --open {defeat} -p{ports} --reason -oG "{gnmapFile}" -oN "{nmapFile}"')

		with open(f'{xmlFile}', 'w') as f:
			f.write(scanner.get_nmap_last_output().decode('UTF-8'))

		with open(f'{csvFile}', 'w') as f:
			f.write(scanner.csv())

		print()

		host_width = 20
		proto_width = 9
		port_width = 7
		state_width = 6
		service_width = 15
		hostname_width = 15
		product_width = 35
		version_width = 15

		print()
		PrintLineColored("{:<{host_width}} {:<{hostname_width}} {:<{proto_width}} {:<{port_width}} {:<{state_width}} {:<{service_width}} {:<{product_width}} {:<{version_width}}".format(
			"IP", "HOSTNAME", "PROTOCOL", "PORT", "STATE", "SERVICE", "PRODUCT", "VERSION", 
			host_width=host_width, proto_width=proto_width, port_width=port_width, state_width=state_width, 
			service_width=service_width, hostname_width=hostname_width, product_width=product_width, version_width=version_width), "white")

		for host in scanner.all_hosts():
			if scanner[host].state() == 'up':
				for proto in scanner[host].all_protocols():
					lport = scanner[host][proto].keys()
					for port in lport:
						if scanner[host][proto][port]['state'] == 'open':
							protocol = proto.upper()
							product = scanner[host][proto][port]['product']
							version = scanner[host][proto][port]['version']
							service = scanner[host][proto][port]["name"]
							PrintLineColored("{:<{host_width}} {:<{hostname_width}} {:<{proto_width}} {:<{port_width}} {:<{state_width}} {:<{service_width}} {:<{product_width}} {:<{version_width}}".format(
								host, scanner[host].hostname(), protocol, port, "OPEN", service, product, version, 
								host_width=host_width, proto_width=proto_width, port_width=port_width, state_width=state_width, 
								service_width=service_width, hostname_width=hostname_width, product_width=product_width, version_width=version_width), "green")

	except Exception as e:
	#	PrintLineColored(e, "red")
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


def IsValidIPnetwork(address):
	try:
		ip = ipaddress.ip_network(address)
		return True
	except ValueError:
		return False


def IsValidCommaSepHosts(address):
	if address.count(",") >= 1:
		addresses = address.split(',')
		for addr in addresses:
			if not IsValidIPaddress(addr) and not IsValidIPnetwork(addr) and not IsValidHostname(addr):
				return False
		return True


def IsValidSpaceSepHosts(address):
	if address.count(" ") >= 1:
		addresses = address.split(' ')
		for addr in addresses:
			if not IsValidIPaddress(addr) and not IsValidIPnetwork(addr) and not IsValidHostname(addr):
				return False
		return True


def is_platform_windows():
    return platform.system() == "Windows"


def is_platform_linux():
    return platform.system() == "Linux"


def CheckNmapInstallation():
	try:
		subprocess.check_output(["nmap", "--version"])
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
		PrintLineColored("https://github.com/beproactivegr/network-scanner.", "cyan")
		print()

		CheckNmapInstallation()
		print()


		target = GetUserInput("Please provide an IP(4/6) address, a network subnet or a hostname(FQDN) to scan: ")

		while not IsValidIPaddress(target) and not IsValidHostname(target) and not IsValidIPnetwork(target) and not IsValidCommaSepHosts(target) and not IsValidSpaceSepHosts(target):
			PrintLineColored("Please provide a valid hostname, IP4, IP6 address or a network subnet.", "yellow")
			target = GetUserInput("Please provide an IP(4/6) address, a network subnet or a hostname(FQDN) to scan: ")


		ports = GetUserInput("Please provide port ranges. Ex: 22; 1-65535; 80,443,8080; all; top-100: ")

		while not IsValidPort(ports):
			PrintLineColored("Please provide valid port ranges.", "yellow")
			ports = GetUserInput("Please provide port ranges. Ex: 22; 1-65535; 80,443,8080; all; top-100: ")


		proto = GetUserInput("Please provide the protocol to scan (tcp/udp): ")

		while not IsValidProto(proto):
			PrintLineColored("Please provide a valid protocol.", "yellow")
			proto = GetUserInput("Please provide the protocol to scan (tcp/udp): ")


		print()

		protoForPrint = proto.upper()
		PrintLineColored(f'Scanning {protoForPrint} ports {ports} on host/s {target}.\nThis may take a while...', "cyan")
		print()

		CreateDir('logs')
		destination = os.path.join(os.getcwd(), 'logs')

		scanner = nmap.PortScanner()
		scan_thread = Thread(target=ScanHost, args=(scanner, target, proto, ports, destination,))
		scan_thread.start()

		while True:
			scan_thread.join(timeout=3)
			if not scan_thread.is_alive():
				break
			PrintFlushColored("..", "green")


		print()
		print()

		scanServices = GetUserInput("Would you like to determine service/version info? (yes/no): ")

		if scanServices == 'yes' or scanServices == 'y':

			print()
			PrintLineColored(f'Scanning {protoForPrint} services on open ports {ports} for live host/s {target}.\nThis may take a while...', "cyan")
			print()

			scan_thread = Thread(target=ScanHostServices, args=(scanner, proto, destination,))
			scan_thread.start()

			while True:
				scan_thread.join(timeout=3)
				if not scan_thread.is_alive():
					break
				PrintFlushColored("..", "green")

		print()
		print()

	except KeyboardInterrupt:
		sys.exit(0)

