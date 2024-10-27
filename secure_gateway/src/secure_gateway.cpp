#include <iostream>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>

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
    std::cout << "This is a test program for capturing traffic at the network level" << std::endl;

    // IPv4 address of the interface we want to sniff
    std::string interfaceIPAddr = "192.168.13.68";

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

    // collect stats from packet
    stats->consumePacket(parsedPacket);

    // return false means we don't want to stop capturing after this callback
    return false;
}
