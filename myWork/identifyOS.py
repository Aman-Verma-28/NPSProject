import nmap
nm=nmap.PortScanner()
print(nm.scan('127.0.0.1', '22-443'))
print(nm.command_line())


output = '''
[
    {
        "accuracy": "100",
        "cpe": "cpe:/o:linux:linux_kernel:2.6",
        "line": "45249",
        "name": "Linux 2.6.14 - 2.6.34",
        "osclass": {
            "accuracy": "100",
            "osfamily": "Linux",
            "osgen": "2.6.X",
            "type": "general purpose",
            "vendor": "Linux"
        }
    },
]

'''