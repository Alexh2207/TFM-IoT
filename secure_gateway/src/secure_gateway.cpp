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

#define MODULE 1

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

/**
 * A struct for collecting packet statistics
 */
struct PacketStats
{
    int ethPacketCount = 0;
    int ipv4PacketCount = 0;
    int ipv6PacketCount = 0;
    int tcpPacketCount = 0;
    int udpPacketCount = 0;
    int dnsPacketCount = 0;
    int httpPacketCount = 0;
    int sslPacketCount = 0;

    std::vector<PacketInfo> packets;

    /**
     * Clear all stats
     */
    void clear() { ethPacketCount = ipv4PacketCount = ipv6PacketCount = tcpPacketCount = udpPacketCount = dnsPacketCount = httpPacketCount = sslPacketCount = 0; }

    // Constructor is optional here since the members are already initialized
    PacketStats() = default;

    /**
     * Collect stats from a packet
     */
    void consumePacket(pcpp::Packet& packet)
    {
        if (packet.isPacketOfType(pcpp::Ethernet))
            ethPacketCount++;
        if (packet.isPacketOfType(pcpp::IPv4))
            ipv4PacketCount++;
        if (packet.isPacketOfType(pcpp::IPv6))
            ipv6PacketCount++;
        if (packet.isPacketOfType(pcpp::TCP))
            tcpPacketCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            udpPacketCount++;
        if (packet.isPacketOfType(pcpp::DNS))
            dnsPacketCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            httpPacketCount++;
        if (packet.isPacketOfType(pcpp::SSL))
            sslPacketCount++;
    }

    /**
     * Print stats to console
     */
    void printToConsole()
    {

        for(auto i:packets)
        {
            std::cout << "------------------" << std::endl
                << "Total data length: " << i.packet_size << std::endl
                << "Source IP: " << i.src_ip << std::endl
                << "Source port: " << i.src_port << std::endl
                << "Destiny IP: " << i.dst_ip << std::endl
                << "Destiny port: " << i.dst_port << std::endl
                << "Packet type: " << i.control_protocol << std::endl
                << "----------------" << std::endl;
        }
        std::cout
            << "Ethernet packet count: " << ethPacketCount << std::endl
            << "IPv4 packet count:     " << ipv4PacketCount << std::endl
            << "IPv6 packet count:     " << ipv6PacketCount << std::endl
            << "TCP packet count:      " << tcpPacketCount << std::endl
            << "UDP packet count:      " << udpPacketCount << std::endl
            << "DNS packet count:      " << dnsPacketCount << std::endl
            << "HTTP packet count:     " << httpPacketCount << std::endl
            << "SSL packet count:      " << sslPacketCount << std::endl;
    }
};

static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);


int main(int argc, char* argv[])
{
    if(MODULE == 0){
        std::cout << "This is a test program for capturing traffic at the network level" << std::endl;

        // IPv4 address of the interface we want to sniff
        std::string interfaceIPAddr = "192.168.1.20";

        // find the interface by IP address
        auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
        if (dev == nullptr)
        {
            std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
            return 1;
        }
        // before capturing packets let's print some info about this interface
        std::cout
            << "Interface info:" << std::endl
            << "   Interface name:        " << dev->getName() << std::endl // get interface name
            << "   Interface description: " << dev->getDesc() << std::endl // get interface description
            << "   MAC address:           " << dev->getMacAddress() << std::endl // get interface MAC address
            << "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
            << "   Interface MTU:         " << dev->getMtu() << std::endl; // get interface MTU

        if (!dev->getDnsServers().empty())
        {
            std::cout << "   DNS server:            " << dev->getDnsServers().front() << std::endl;
        }

        // open the device before start capturing/sending packets
        if (!dev->open())
        {
            std::cerr << "Cannot open device" << std::endl;
            return 1;
        }

        PacketStats stats;

        std::cout << std::endl << "Starting capture in blocking mode..." << std::endl;

        // clear stats
        stats.clear();

        // start capturing in blocking mode. Give a callback function to call to whenever a packet is captured, the stats object as the cookie and a 10 seconds timeout
        dev->startCaptureBlockingMode(onPacketArrivesBlockingMode, &stats, 5);

        // thread is blocked until capture is finished

        // capture is finished, print results
        std::cout << "Results:" << std::endl;
        stats.printToConsole();

        return 0;
    }else{
        Sniffer sniff = Sniffer("192.168.35.68");

        int check = sniff.start();
        if(check == 1){
            return 1;
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));

        sniff.stop();

        return 0;
    }
}

/**
 * a callback function for the blocking mode capture which is called each time a packet is captured
 */
static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    // extract the stats object from the cookie
    auto* stats = static_cast<PacketStats*>(cookie);

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    auto* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    if (ipLayer == nullptr)
    {
        std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
        return false;
    }

    PacketInfo info;

    info.packet_size = ipLayer->getDataLen();

    info.dst_ip = ipLayer->getDstIPAddress();

    std::cout << ipLayer->getDstIPAddress() << std::endl;
    info.src_ip = ipLayer->getSrcIPAddress();

    auto* controlLayer = ipLayer->getNextLayer();

    switch (controlLayer->getProtocol())
    {
    case pcpp::TCP:
        {
            info.control_protocol = TCP;
            auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            info.dst_port = tcpLayer->getDstPort();
            info.src_port = tcpLayer->getSrcPort();
        }
        break;

    case pcpp::UDP:
        {
            info.control_protocol = UDP;
            auto* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
            info.dst_port = udpLayer->getDstPort();
            info.src_port = udpLayer->getSrcPort();
        }
        break;

    case pcpp::ICMP:
        info.control_protocol = ICMP;
        break;
    
    default:
        info.control_protocol = UNK;
        break;
    }

    stats->packets.push_back(info);

    stats->consumePacket(parsedPacket);

    // return false means we don't want to stop capturing after this callback
    return false;
}
