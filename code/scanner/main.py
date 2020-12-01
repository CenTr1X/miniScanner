from argparse import ArgumentParser
from port_scanner import ports_scan
from os_scanner import os_scan 

def main():
    usage = "Usage: %prog -i <ip address>"
    parser = ArgumentParser(usage=usage)
    parser.add_argument("-i", "--ip", type=str, dest="ip", help="get the ip of target(s), divided by '-'")
    parser.add_argument("-m", "--mod", type=str, dest="scan_mod", default="valuable", help="choose to scan all ports or just top ports")
    parser.add_argument("-p", "--port", type=str, dest="port", default="1-65536", help="input the port range, divided by '-'")
    parser.add_argument("-t", "--timeout", type=int, dest="timeout", default=5, help="get the maximum time to connect")
    parser.add_argument("-tc", "--threads_count", type=int, dest="threads_count", default=50, help="get the number of threads")
    parser.add_argument("-top", "--top", type=int, dest="top", default="100", help="get the number of top ports if using valuable mod")
    parser.add_argument("-o", "--os", help="to scan os type", action="store_true")
    parser.add_argument("-v", "--verbose", help="show closed ports", action="store_true")
    args = parser.parse_args()
    print(args)
    if not args.ip:
        print(usage)
        return
    elif "-" in args.ip:
        try:
            ip1, ip2 = args.ip.split("-")[0], args.ip.split("-")[1]
            arr1, arr2 = ip1.split("."), ip2.split(".")
            if arr1[:-1] == arr2[:-1]:
                start_port, end_port = get_port_range(args.port)
                if start_port < 0 or end_port < 0:
                    print("invalid port number")
                    return
                for i in range(int(arr1[-1]), int(arr2[-1]) + 1):
                    res = ports_scan(arr1[0] + '.' + arr1[1] + '.' + arr2[2] + '.' + str(i), args.scan_mod, args.timeout, \
                        start_port, end_port, args.top, args.threads_count)
            else:
                print("the minimum of subnet mask is 24")
                print("use format like 192.168.0.1-192.168.0.20")
                return 
        except Exception as e:
            print(e)
            print("invalid ip")
            return
    else:
        start_port, end_port = get_port_range(args.port)
        if start_port < 0 or end_port < 0:
            print("invalid port number")
            return
        res = ports_scan(args.ip, args.scan_mod, args.timeout, start_port, end_port, args.top, args.threads_count)
        print(res)

def get_port_range(port_str):
    try:
        if '-' in port_str:
            start, end = int(port_str.split('-')[0]), int(port_str.split('-')[1])
        else:
            start = end = int(port_str)
        return start, end
    except:
        print("invalid port range")
        return -1, -1

def show(res, verbose):
    if verbose:
        print(res)
    else:
        for port in res:
            if res[port] == "Open":
                print(port, ": ", res[port])

if __name__ == "__main__":
    main()