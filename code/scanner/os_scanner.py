import os, re

def os_scan(ip):
    ttl_res = ttl_scan(ip)
    nmap_res = nmap_scan(ip)
    print(ttl_res)

def ttl_scan(ip):
    str_match = re.compile(r'TTL=\d+')
    num_match = re.compile(r'\d+')
    res = os.popen("ping -n 1 " + ip).read()
    for line in res.splitlines():
        ttl_str = str_match.findall(line)
        if ttl_str:
            ttl = int(num_match.findall(ttl_str[0])[0])
            if ttl <= 64:
                return "Linux/Unix"
            else:
                return "Windows"

def nmap_scan(ip):
    pass

if __name__ == "__main__":
    os_scan("10.10.10.129")
