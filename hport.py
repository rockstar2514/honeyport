port = 31337
whitelist = [""]
logfile = "hport.log"
response = "GO AWAY!!"

import socket
import sys, getopt
import os
import datetime
import logging

if not os.getuid()==0:
		sys.exit("\n[!] Root Priveleges required to modify firewall rules.\n")

if port >= 1 and port <= 65535:
		try:
				s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s_socket.bind(("0.0.0.0", port))
		except socket.error as e:
				sys.exit("[!] Unable to bind to port with error: {0} -- {1} ".format(e[0], e[1]))
else:
		print("[!] Please specify a valid port range (1-65535) in the configuration.")
		sys.exit(2)

logger = logging.getLogger('hp')
formatter = logging.Formatter("%(message)s - %(asctime)s","%c")
shdlr = logging.StreamHandler()
logger.addHandler(shdlr)
shdlr.setFormatter(formatter)
if logfile != "":
		try:
				fhdlr = logging.FileHandler(logfile)
				fhdlr.setFormatter(formatter)
				logger.addHandler(fhdlr)
		except IOError as e:
				sys.exit("[!] Unable to create/append logfile: {0} -- {1} ".format(e[0], e[1]))
logger.setLevel(logging.INFO)
logger.propagate = True

s_socket.listen(5)
host_ip = s_socket.getsockname()[0]
logger.info("[*] Starting Honeyport listener on port {0}. Waiting for the bees...".format(port))

while True:
		c, addr = s_socket.accept()
		client_ip = str(addr[0])
		if client_ip in (whitelist, "127.0.0.1"):
				logger.info("[!] Hit from whitelisted IP: {0}".format(client_ip))
				c.shutdown(socket.SHUT_RDWR)
				c.close()
		else:
				if response_script == "":
						if sys.version_info < (3,0):
								c.sendall(response)
						else:
								c.sendall(bytes(response, 'UTF-8'))
				else:
						res = check_output(["python", response_script, client_ip])
				if sys.version_info < (3,0):
						c.sendall(res)
				else:
						c.sendall(bytes(res, 'UTF-8'))
				c.shutdown(socket.SHUT_RDWR)
				c.close()
				try:
						result = check_output(["/sbin/iptables", "-A", "INPUT", "-s", "{0}".format(client_ip), "-j", "DROP"])
						logger.info("[+] Blacklisting: {0} with IPTABLES (TTL: {1})".format(client_ip, "Permanent"))
				except (OSError,CalledProcessError) as e:
						logger.error("[!] Failed to blacklist {0} with IPTABLES ({1}), is iptables on the PATH?".format(client_ip, e))
