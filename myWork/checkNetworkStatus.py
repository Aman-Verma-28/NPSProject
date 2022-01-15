import nmap
nm=nmap.PortScanner()
print(nm.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389', ports='22-443', sudo=True))
hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    print('{}:{}'.format(host, status))


Output = '''
192.168.1.0:down
192.168.1.1:up
192.168.1.10:down
192.168.1.100:down
192.168.1.101:down
192.168.1.102:down
192.168.1.103:down
192.168.1.104:down
192.168.1.105:down
'''
