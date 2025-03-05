#include "sniffer.h"
#include "filter.h"

//Included for testing
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <sys/wait.h>
#include <iostream>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IcmpLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>

#define MODULE 1

#define CHAIN "INPUT"

#define ACCEPT "ACCEPT"


int add_iptables_rule(std::string src_ip, std::string dst_ip, std::string proto, int src_port, int dst_port, char* action);
int delete_iptables_rule(std::string src_ip, std::string dst_ip, std::string proto, int src_port, int dst_port, char* action);


int main(int argc, char* argv[])
{
    if(MODULE == 0){

        int result = add_iptables_rule("10.0.0.1","10.0.0.1", "cp",80,80, ACCEPT);

        std::cout << result << std::endl;

        char* argument_list_L[] = {"iptables","-L",NULL};

        result = delete_iptables_rule("10.0.0.1","10.0.0.1", "tcp",80,80, ACCEPT);

        std::cout << result << std::endl;
        
    }else{

        Filter filter = Filter("INPUT");

        int result = filter.add_iptables_rule("10.0.0.1","10.0.0.1", "tcp",80,80, ACCEPT);

        std::cout << result << std::endl;

        sleep(10);

        result = filter.delete_iptables_rule("10.0.0.1","10.0.0.1", "tcp",80,80, ACCEPT);

        std::cout << result << std::endl;

    }

    return 0;
}
