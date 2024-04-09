import nmap  # Import the nmap module

# Create a new Nmap Scanner instance
nm = nmap.PortScanner()

# Define the target for the scan
target = 'scanme.nmap.org'

# Perform an Nmap scan on the target
nm.scan(hosts=target, arguments='-p 22,80,443 -sC -sV')  # Scanning for ports 22, 80, and 443

# Get the scan results
scan_results = nm.csv()  # Get the results in CSV format

# Specify the filename to write the results to
filename = 'nmap_scan_results.csv'

# Write the scan results to a file
with open(filename, 'w') as file:
    file.write(scan_results)

print(f'Scan results have been saved to {filename}')
