import xml.etree.ElementTree as ET
import subprocess
import asyncio
import sys


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
	
	
async def execute11(line):
    cmd = "openssl s_client -connect %s < /dev/null 2>/dev/null | openssl x509 -fingerprint -noout -in /dev/stdin" % line
    fp_ = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await fp_.communicate()
    f[line] = stdout
    return f
	
	
print(f"""{bcolors.HEADER}
 _____ _           _ ____                        ____          _
 |  ___(_)_ __   __| / ___|  __ _ _ __ ___   ___ / ___|___ _ __| |_
 | |_  | | '_ \ / _` \___ \ / _` | '_ ` _ \ / _ \ |   / _ \ '__| __|
 |  _| | | | | | (_| |___) | (_| | | | | | |  __/ |__|  __/ |  | |_
 |_|   |_|_| |_|\__,_|____/ \__,_|_| |_| |_|\___|\____\___|_|   \__|
{bcolors.ENDC}"""
)


argc = len(sys.argv)
if argc == 1 or argc == 2:
	print('Usage:\n\tpython3 FindSameCert.py domain:port nmap.xml')
	print('For example:\n\tpython3 FindSameCert.py kkk.com:443 nmap.xml')
	sys.exit()
else:
	url = sys.argv[1]
	nmap = sys.argv[2]

	
tree = ET.parse(nmap)
root = tree.getroot()


SslPorts = []
ListDomCheck = {}
hosts = root.findall('host')


for host in hosts:
    try:
        HostNameElem = host.findall('hostnames')
        HostName = HostNameElem[0].findall('hostname')[0].attrib['name']
        PortElement = host.findall('ports')
        ports = PortElement[0].findall('port')
        for port in ports:
            service = port.findall('service')[0].attrib['name']
            if "tunnel" in port.findall('service')[0].attrib:
                _port = port.attrib['portid']
                SslPorts.append(_port)
            SslPortsCopy = SslPorts.copy()
            ListDomCheck[HostName] = SslPortsCopy
        SslPorts.clear()
    except:
        pass


DomainList = []
for i in ListDomCheck:
    for j in range(len(ListDomCheck[i])):
        line = i+":"+ListDomCheck[i][j]
        DomainList.append(line)


f = {}


cmd = "openssl s_client -connect %s < /dev/null 2>/dev/null | openssl x509 -fingerprint -noout -in /dev/stdin" %url
fp = subprocess.Popen([cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0]
print (f"{bcolors.HEADER}TLS certificate fingerprint for %s:{bcolors.ENDC}" %url)
print(fp.decode("utf-8"))


futures = [execute11(domain) for domain in DomainList]


loop = asyncio.get_event_loop()
fp_ = loop.run_until_complete(asyncio.wait(futures))


print(f"{bcolors.HEADER}The same TLS certificate is used on:{bcolors.ENDC}")
for k, v in f.items():
    if v == fp:
        print(f"{bcolors.BOLD}%s{bcolors.ENDC}" %k)
