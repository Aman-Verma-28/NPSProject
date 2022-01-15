import nmap

nm = nmap.PortScanner()
try:
    print("raw_json:", nm.scan('45.33.32.156', '22-443'))

    print('commandline:', nm.command_line())
    print('scan info:', nm.scaninfo())
    print('hosts:', nm.all_hosts())

    print('available protocols:', nm['45.33.32.156'].all_protocols())
    print('TCP ports(22-443): ', nm['45.33.32.156']['tcp'].keys())
    print('port 22 has tcp: ', nm['45.33.32.156'].has_tcp(22))
    print('port 23 has tcp: ', nm['45.33.32.156'].has_tcp(23))
    print('port 22:', nm['45.33.32.156'].tcp(22))
    print('state of the port:', nm['45.33.32.156']['tcp'][22]['state'])

except Exception as e:
    print("exception: ", e)


# for host in nm.all_hosts():
#     print(nm[host].hostname())
#
#     print(nm[host].state())
#
#
#     print(nm[host].all_protocols())
#
#     print(nm[host]['tcp'].keys())
#
#     print(nm[host].has_tcp(22))
#
#     print(nm[host].has_tcp(23))
#
#     print(nm[host]['tcp'][22])
#
#     print(nm[host].tcp(22))
#
#     print(nm[host]['tcp'][22]['state'])



### {'nmap': {'command_line': 'nmap -oX - -p 22-443 -sV 127.0.0.1', 'scaninfo': {'tcp': {'method': 'connect', 'services': '22-443'}}, 'scanstats': {'timestr': 'Fri Jan 14 12:53:10 2022', 'elapsed': '0.34', 'uphosts': '1', 'downhosts': '0', 'totalhosts': '1'}}, 'scan': {'127.0.0.1': {'hostnames': [{'name': 'localhost', 'type': 'PTR'}], 'addresses': {'ipv4': '127.0.0.1'}, 'vendor': {}, 'status': {'state': 'up', 'reason': 'conn-refused'}}}}
