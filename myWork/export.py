import nmap
nm = nmap.PortScanner()
nm.scan('45.33.32.156', '22-443')
print("Exporting in form of CSV: ")
print("----------------------------")
print(nm.csv())
print("----------------------------")

