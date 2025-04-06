
#ifndef __SNIFFER__
#define __SNIFFER__


#include <iostream>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IcmpLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include "thread_queue.h"

class Sniffer{

    private:

    pcpp::PcapLiveDevice* dev;

    public:

    typedef enum{UDP,TCP,ICMP,UNK}ctrl_prot;

    /**
     * Useful packet information struct
     */

    typedef struct 
    {
        size_t packet_size;
        pcpp::IPAddress src_ip;
        pcpp::IPAddress dst_ip;
        ctrl_prot control_protocol;
        int src_port;
        int dst_port;
    }PacketInfo;

    Thread_queue<PacketInfo> processed_packet_q;

    Sniffer();

    Sniffer(std::string IPAddresses);

    int start();

    void stop();

    ~Sniffer();

    private:
    
    std::vector<PacketInfo> packets;

};


#endif
