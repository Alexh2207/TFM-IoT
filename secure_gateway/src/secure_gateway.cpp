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


int main(int argc, char* argv[])
{
    if(MODULE == 0){

        char* argument_list[] = {"iptables","-L",NULL};

        execvp("/usr/sbin/iptables",argument_list);
        
    }else{



    }

    return 0;
}
