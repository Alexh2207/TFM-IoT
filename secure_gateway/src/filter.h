
#ifndef __FILTER__
#define __FILTER__


#include <iostream>

class Filter{

    private:

    char* chain;

    public:

    static const char* ACCEPT;
    static const char* DROP;

    Filter();

    Filter(char* chain);

    int add_iptables_rule(std::string src_ip, std::string dst_ip, std::string proto, int src_port, int dst_port, char* action);

    int delete_iptables_rule(std::string src_ip, std::string dst_ip, std::string proto, int src_port, int dst_port, char* action);

    ~Filter();

};


#endif
