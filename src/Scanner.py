"""
This Module will build a scanner that will gather information on an IP
Address and then return information in a dictionary
"""

# *=========================
# * Import section
# *=========================

import socket
import json
import pandas as pd

# *==========================
# * Classes Section
# *==========================

class TCP_Scanner:
    """
    This Class will handle the module needed to build a Scanner
    for an IP Address and return the Information in a Clean Format
    """

    @classmethod
    def Scan_IP_Address(
            cls,
            Target_IP: str = "",
            Port_Range: int = ""
    ):
        """
        params:
            Target_IP: The Target IP that is wanted to be scanned

        returns:
            Will return a JSON of the Ports that are open currently
        """

        # Opening up the Sockets needed to send by creating the object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Small function to handle the Check of the Port Number
        def PortCheck(port):
            try:
                sock.connect((Target_IP, port))
                return True
            except:
                return False

        # Running the loop through the range of Ports that is wanted
        for portNumber in range(Port_Range):
            if PortCheck(portNumber):
                print(f"[+] Port {portNumber}: Open")

