
# Domain Name Blacklist

This system uses pcap to dump TCP hits and convert that to domain names.
Then it checks the domain name against a blacklist. On a match it sends
the IP to ipset so it gets blocked at least for the next it gets used.

# Dependencies

At least you will need to install the development version of the pcap library.

    sudo apt-get install libpcap-dev

