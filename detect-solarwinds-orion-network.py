import nmap
import csv

scan_hosts = ['172.16.0.0/16', '172.27.0.0/18', '172.29.0.0/18']
port = 17777


def main():
    devices_detected = []
    scanner = nmap.PortScanner()
    for scan_host in scan_hosts:
        scan = scanner.scan(hosts=scan_host, arguments='-sV -p ' + str(port) + ' -T4 -A')
        hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
        for host in hosts_list:
            if host[1] == 'up':
                host_ip = host[0]
                if scan['scan'][host_ip]['tcp'][port]['state'] == 'open':
                    devices_detected.append(host_ip)
    with open('devices-with-orion.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        for device in devices_detected:
            writer.writerow([device])


if __name__ == '__main__':
    main()
