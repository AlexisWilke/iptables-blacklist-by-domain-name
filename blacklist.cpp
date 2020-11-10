
// pcap docs:   https://linux.die.net/man/3/pcap

#include    <boost/algorithm/string/replace.hpp>

#include    <algorithm>
#include    <cstring>
#include    <cctype>
#include    <fstream>
#include    <iostream>
#include    <map>
#include    <memory>
#include    <string>

#include    <netdb.h>
#include    <net/ethernet.h>
#include    <netinet/ip.h>
#include    <netinet/tcp.h>
#include    <netinet/udp.h>
#include    <pcap.h>



std::string const g_config = "/etc/blacklist/blacklist.conf";

typedef std::map<std::string, std::string>      params_t;

typedef std::vector<std::string>                blacklist_t;

char g_errbuf[PCAP_ERRBUF_SIZE];



bool my_isspace(char ch)
{
    return std::isspace(static_cast<unsigned char>(ch));
}


class cached_ip
{
public:
    typedef std::shared_ptr<cached_ip>      pointer_t;
    typedef std::map<in_addr_t, pointer_t>  map_t;

                            cached_ip() : f_last_access(time(nullptr)) {}

    void                    access() { f_last_access = time(nullptr); }

    void                    searched() { f_searched = true; }
    bool                    was_searched() const { return f_searched; }

    void                    blacklisted() { f_blacklisted = true; }
    bool                    was_blacklisted() const { return f_blacklisted; }

    void                    set_host(std::string const & host);
    std::string const &     get_host() const { return f_host; }
    bool                    has_host() const { return !f_host.empty(); }

    bool                    match(blacklist_t const & blacklist);

private:
    bool                    f_searched = false;
    bool                    f_blacklisted = false;
    time_t                  f_last_access = 0;
    std::string             f_host = std::string();
};


void cached_ip::set_host(std::string const & host)
{
    if(host.empty())
    {
        throw std::logic_error("set_host() called with an empty string");
    }
    if(host[0] == '.')
    {
        f_host = host;
    }
    else
    {
        f_host = "." + host;
    }
}


bool cached_ip::match(blacklist_t const & blacklist)
{
    for(auto & b : blacklist)
    {
        if(b.length() > f_host.length())
        {
            // host name small than the blacklist URL, skip
            continue;
        }
        if(strcmp(b.c_str(), f_host.c_str() + f_host.length() - b.length()) == 0)
        {
            // this is a match
            //
            blacklisted();
            return true;
        }
    }

    return false;
}



class pcap_filter
{
public:
                        pcap_filter();
                        ~pcap_filter();

    std::string         get_value(std::string const & name) const;
    void                init();
    void                run();

    void                handle_packet(pcap_pkthdr const * header, u_char const * packet);
    void                handle_ipv4(in_addr const & dst, int port, int flags);

private:
    params_t            f_params = params_t();
    pcap_t *            f_pcap = nullptr;
    bool                f_program_compiled = false;
    bpf_program         f_program = bpf_program();
    std::string         f_ipset_add = std::string();
    blacklist_t         f_blacklist = blacklist_t();
    cached_ip::map_t    f_cached_ip = cached_ip::map_t();
};


void static_handle_packet(u_char * filter, pcap_pkthdr const * header, u_char const * packet)
{
    reinterpret_cast<pcap_filter *>(filter)->handle_packet(header, packet);
}


pcap_filter::pcap_filter()
{
    std::ifstream in(g_config);
    std::size_t line(0);
    std::string var;
    while(getline(in, var))
    {
        ++line;
        std::remove_if(var.begin(), var.end(), my_isspace);
        if(var.empty())
        {
            continue;
        }
        if(var[0] == '#')
        {
            continue;
        }
        std::string::size_type const pos(var.find('='));
        std::string name(var.substr(0, pos));
        std::remove_if(name.begin(), name.end(), my_isspace);
        if(name.empty())
        {
            std::cerr << "error:" << line << ": variable name can't be empty." << std::endl;
            exit(1);
        }
        std::string value(var.substr(pos + 1));

        if(name == "blacklist")
        {
            if(!value.empty())
            {
                if(value[0] != '.')
                {
                    value = "." + value;
                }
                // TODO: do more validations such as double dots, invalid dashes, etc.
                f_blacklist.push_back(value);
            }
        }
        else
        {
            f_params[name] = value;
        }
    }
}


pcap_filter::~pcap_filter()
{
    if(f_program_compiled)
    {
        pcap_freecode(&f_program);
    }

    pcap_close(f_pcap);
}


std::string pcap_filter::get_value(std::string const & name) const
{
    auto it(f_params.find(name));
    if(it == f_params.end())
    {
        return std::string();
    }
    return it->second;
}


void pcap_filter::init()
{
    std::string init_ipset(get_value("create_ipset"));
    if(init_ipset.empty())
    {
        init_ipset = "ipset -exist create blacklist hash:ip family inet timeout 0 counters";
    }
    if(system(init_ipset.c_str()) != 0)
    {
        int const e(errno);
        std::cerr << "error: could not initialize the blacklist ipset." << std::endl;
        std::cerr << "error: " << strerror(e) << std::endl;
        exit(1);
    }

    f_ipset_add = get_value("ipset");
    if(f_ipset_add.empty())
    {
        f_ipset_add = "ipset add blacklist [ip]";
    }

    std::string device(get_value("interface"));
    if(device.empty())
    {
        device = "any";
    }

    std::string const promiscuous(get_value("promiscuous"));

    int ms(20); // 20ms by default
    std::string timeout(get_value("timeout"));
    if(!timeout.empty())
    {
        ms = std::stoi(timeout);
    }

    f_pcap = pcap_open_live(
              device.c_str()
            , IP_MAXPACKET
            , promiscuous == "on"
            , ms
            , g_errbuf);
    if(f_pcap == nullptr)
    {
        std::cerr
            << "error: opening a live pcap handle failed with: \""
            << g_errbuf
            << "\"."
            << std::endl;
        exit(1);
    }

    // filter such as "src host 10.10.10.3"
    //
    std::string filter(get_value("filter"));
    if(filter.empty())
    {
        // TBD: see whether we can limit to just entries with a useful IP
        //
        filter = "";
    }
    // TODO: support the netmask (last parameter)
    f_program_compiled = pcap_compile(f_pcap, &f_program, filter.c_str(), 1, 0) != -1;
    if(!f_program_compiled)
    {
        std::cerr
            << "error: an error occured compiling the pcap filter: "
            << pcap_geterr(f_pcap)
            << std::endl;
        exit(1);
    }
}


void pcap_filter::run()
{
    pcap_loop(f_pcap, 0, &::static_handle_packet, reinterpret_cast<u_char *>(this));
}


void pcap_filter::handle_packet(pcap_pkthdr const * header, u_char const * packet)
{
    ether_header const * ether(reinterpret_cast<ether_header const *>(packet));
    if(ntohs(ether->ether_type) != ETHERTYPE_IP)
    {
std::cerr << "unexpected type (not IP)\n";
        return;
    }

    ip const * ip_info(reinterpret_cast<ip const *>(packet + sizeof(ether_header)));

    // valid IP header size?
    std::size_t const ip_size(ip_info->ip_hl << 2);
    if(ip_size < (sizeof(ip)))
    {
std::cerr << "invalid size?! " << ip_info->ip_hl << " vs " << (sizeof(ip) >> 2) << "\n";
        return;
    }

    if(ip_info->ip_p == IPPROTO_UDP)
    {
        udphdr const * udp_info(reinterpret_cast<udphdr const *>(packet + ip_size));
        handle_ipv4(ip_info->ip_dst, ntohs(udp_info->uh_dport), NI_DGRAM);
    }
    else if(ip_info->ip_p == IPPROTO_TCP)
    {
        tcphdr const * tcp_info(reinterpret_cast<tcphdr const *>(packet + ip_size));
        handle_ipv4(ip_info->ip_dst, ntohs(tcp_info->th_dport), 0);
    }
    //else -- ignore the rest
}


void pcap_filter::handle_ipv4(in_addr const & dst, int port, int flags)
{
    cached_ip::pointer_t cache(f_cached_ip[dst.s_addr]);

    // create it if it doesn't exist yet
    //
    if(cache == nullptr)
    {
        cache = std::make_shared<cached_ip>();
        f_cached_ip[dst.s_addr] = cache;
    }

    // update last access time so it stays longer in the cache
    //
    cache->access();

    // did we search it yet?
    //
    if(cache->was_searched())
    {
        // it was already worked on, we're done
        //
        return;
    }

    cache->searched();

    char host[NI_MAXHOST];

    sockaddr_in addr = sockaddr_in();
    addr.sin_family = AF_INET;
    addr.sin_port = port;
    addr.sin_addr = dst;

    int const r(getnameinfo(
                  reinterpret_cast<sockaddr const *>(&addr)
                , sizeof(addr)
                , host
                , sizeof(host)
                , nullptr
                , 0
                , flags | NI_NAMEREQD
            ));

    if(r != 0)
    {
        // could not determine domain name
        return;
    }

    cache->set_host(host);

    // now check whether this domain name is blacklisted
    //
    if(cache->match(f_blacklist))
    {
        // this is a match, block that IP address
        //
        char host_ip[NI_MAXHOST];
        int const q(getnameinfo(
                      reinterpret_cast<sockaddr const *>(&addr)
                    , sizeof(addr)
                    , host_ip
                    , sizeof(host_ip)
                    , nullptr
                    , 0
                    , flags | NI_NUMERICHOST
                ));
        if(q != 0)
        {
            std::cerr << "error: getnameinfo() could not convert the IPv4 to a string." << std::endl;
            exit(1);
        }
        std::string add(f_ipset_add);
        boost::replace_all(add, "[ip]", host_ip);
        if(system(add.c_str()) != 0)
        {
            // it may be that all will fail, but this is not a fatal error
            //
            int const e(errno);
            std::cerr
                << "warning: \""
                << add
                << "\" command failed with: "
                << strerror(e)
                << std::endl;
        }
    }
}




void usage()
{
    std::cout << "Usage: blacklist" << std::endl;
    std::cout << "  and edit the " << g_config << std::endl;
}



int main(int argc, char * argv[])
{
    for(int i(1); i < argc; ++i)
    {
        if(strcmp(argv[i], "-h") == 0
        || strcmp(argv[i], "--help") == 0)
        {
            usage();
            return 9;
        }
        std::cerr << "error: unknown command line option \"" << argv[i] << "\"." << std::endl;
        exit(1);
    }

    pcap_filter filter;
    filter.run();

    return 0;
}


// vim: ts=4 sw=4 et
