
# New "master"

github decided to change the default branch from "master" to "main". This
repository uses the new default.

# Domain Name Blacklist

This system uses pcap to dump TCP hits and convert that to domain names.
Then it checks the domain name against a blacklist. On a match it sends
the IP to ipset so it gets blocked at least for the next it gets used.

## Reverse Lookup Not Working

Most large corporations do not have a PTR that matches the DNS IP addresses
returned. For example, youtube.com gives IP address which PTR use things
such as 1e100.net. All of the google services do that.

This means that this tool is totally useless to block a domain such as
youtube.com.

On the other hand, some companies don't do that. You'll be able to block
`facebook.com` and `fbcdn.net` easily.

## Delays

The pcap library does not always return immediately. We give it 20ms by
default. You can change the delay in the configuration file:

    timout=1000

This means 1 second.

Further, it takes a little time to decypher the packet, grab the IP address,
convert the IP address in a domain name, check whether that domain name is
blacklisted, and finally add that IP address to the blacklist ipset.

As a result, that specific packet will have flown through the firewall. Any
further attempts will be blocked, though. Also, all blacklisted IPs remain
until you reboot or manually empty the blacklist ipset.

# Dependencies

At least you will need to install the development version of the pcap library.

    sudo apt-get install libpcap-dev

I also use cmake and g++ (and git for the repository if you want to clone using
git).

# Firewall Setup

The blacklist tool uses ipset to add new IPs to a list named blacklist. Your
firewall will need to access that list using the ipset extension.

    iptables -A OUTPUT -m set --match-set blacklist dst -j REJECT

WARNING: the name `blacklist` is the name of your ipset. This is the default
I use, but you may want to change that so you'll have to change it here as
well. Also, here I show an example adding the block in the OUTPUT chain, you
may want it in your FORWARD or INPUT chains. You can also limit the rule by
IP address (i.e. only one computer on your LAN). Finally, I use the `-A`, but
if you want to make it work, you're likely to need a `-I` so it gets inserted
at the right place.

# Settings

The tool comes with a configuration file that you want to install under /etc:

    sudo mkdir -p /etc/blacklist
    sudo cp -i blacklist.conf /etc/blacklist/.

Edit the configuration file to add the domain names you want to blacklist.

    blacklist=facebook.com
    blacklist=tiktok.com
    blacklist=instragram.com
    blacklist=tweeter.com
    ...

Those domains and all sub-domains will be blocked.

