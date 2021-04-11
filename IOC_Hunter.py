"""
Description:
----------------------------------------------------------------
This Script will attempt to Discover IOC's and attempt to
ease the process of threat hunting within your environment
"""

# *================================================================
# * Import Section
# *================================================================

from src.ThreatFoxUtils import ThreatFox
from src.ShodanUtils import Shodan
from src.GreyNoiseUtils import Greynoise
import pandas as pd
import time

# *================================================================
# * Main Body
# *================================================================

ShodanHandler = Shodan(
    ApiKey="zpqtBbT4Hxp9W7NO59TMmd8lOLr0Wgac"
)

print("[-] Grabbing IOC Dataset from ThreatFox...")
Data = ThreatFox.query_ioc_database(number_of_days=1)
print("[+] IOC Dataset Grabbed!\n")

for Obj in Data:
    if Obj['ioc_type'] == 'ip:port':
        IP = Obj['ioc'].split(":")[0]
        print(f"[+] Grabbing {IP}")
        GreyNoise_Data = Greynoise.lookup_IP(IP)
        if 'classification' in GreyNoise_Data:
            if GreyNoise_Data['classification'] == 'malicious':
                print(GreyNoise_Data)
        else:
            pass

