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

#define MODULE 0


int main(int argc, char* argv[])
{
    if(MODULE == 0){
        std::string route_text;
        std::ifstream RouteFile("/proc/net/route");
        while (getline(RouteFile,route_text)){
            std::string delimiter = "\t";
            std::string segment;
            std::vector<std::string> route_info;
            std::stringstream ss (route_text);
            while(getline(ss,segment,'\t')){

            }

        }
        
    }else{



    }

    return 0;
}
