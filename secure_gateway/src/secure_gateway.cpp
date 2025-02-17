#include <iostream>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IcmpLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include "sniffer.h"
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#define MODULE 0

#define CHAIN "INPUT"

#define ACCEPT "ACCEPT"


int add_iptables_rule(std::string src_ip, std::string dst_ip, std::string proto, int src_port, int dst_port, char* action);


int main(int argc, char* argv[])
{
    if(MODULE == 0){

        add_iptables_rule("10.0.0.1","10.0.0.1", "tcp",80,80, ACCEPT);
        
    }else{



    }

    return 0;
}

int add_iptables_rule(std::string src_ip, std::string dst_ip, std::string proto, int src_port, int dst_port, char* action){
    char src_ip_local[32];
    char dst_ip_local[32];
    char src_port_local[8];
    char dst_port_local[8];
    char proto_local[8];
    strcpy(src_ip_local, src_ip.c_str());
    strcpy(dst_ip_local, dst_ip.c_str());
    strcpy(src_port_local, std::to_string(src_port).c_str());
    strcpy(dst_port_local, std::to_string(dst_port).c_str());
    strcpy(proto_local, proto.c_str());
    char* argument_list[] = {"iptables","-A", CHAIN, "-s", src_ip_local, "-d", dst_ip_local, "-p", proto_local, "--sport", src_port_local, "--dport", dst_port_local, "-j", action,NULL};

    return execvp("/usr/sbin/iptables",argument_list);
}