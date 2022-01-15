import nmap
nm = nmap.PortScanner()
nm.scan('45.33.32.156', '22-443')

for host in nm.all_hosts():
    print("The hostname: ", nm[host].hostname())
    print("State:", nm[host].state())
    print("All protocols:", nm[host].all_protocols())
    print("All TCP keys: ", nm[host]['tcp'].keys())
    print("If the port 22 is TCP or not: ", nm[host].has_tcp(22))
    print("If the port 23 is TCP or not: ", nm[host].has_tcp(23))
    print(nm[host]['tcp'][22])
    print(nm[host].tcp(22))
    print("state of the port 22: ", nm[host]['tcp'][22]['state'])

# for host in nm.all_hosts():
#     print('Host : %s (%s)' % (host, nm[host].hostname()))
#     print('State : %s' % nm[host].state())
#     print(nm[host].all_protocols())
#     for proto in nm[host].all_protocols():
#         print('----------')
#         print('Protocol : %s' % proto)
        # lport = nm[host][proto].keys()
        # lport.sort()
        # for port in lport:
        #     print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))


