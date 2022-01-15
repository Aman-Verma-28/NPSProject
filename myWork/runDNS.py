import nmap3
nmap = nmap3.Nmap()
results = nmap.nmap_dns_brute_script("your-host.com")

print(results)
