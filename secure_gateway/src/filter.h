
#ifndef __FILTER__
#define __FILTER__


#include <iostream>

class Filter{

    private:

    char* chain;

    public:

    static const char* ACCEPT;
    static const char* DROP;

    typedef struct{
        std::string src_ip;
        std::string dst_ip;
        std::string proto;
        int src_port;
        int dst_port;
        std::string action;
        int add;
    } rule;

    Filter();

    Filter(char* chain);

    int manage_iptables_rule(Filter::rule rule);

    ~Filter();

};


#endif
