#include "sniffer.h"

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);

Sniffer::Sniffer(){
    this->dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName("any");
}

Sniffer::Sniffer(std::string IPAddresses){
    this->dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(IPAddresses);
}

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie){
    
    auto* stats = static_cast<std::vector<Sniffer::PacketInfo>*>(cookie);

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    auto* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    if (ipLayer == nullptr)
    {
        std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
    }

    Sniffer::PacketInfo info;

    info.packet_size = ipLayer->getDataLen();

    info.dst_ip = ipLayer->getDstIPAddress();

    std::cout << ipLayer->getDstIPAddress() << std::endl;
    info.src_ip = ipLayer->getSrcIPAddress();

    auto* controlLayer = ipLayer->getNextLayer();

    switch (controlLayer->getProtocol())
    {
    case pcpp::TCP:
        {
            info.control_protocol = Sniffer::TCP;
            auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            info.dst_port = tcpLayer->getDstPort();
            info.src_port = tcpLayer->getSrcPort();
        }
        break;

    case pcpp::UDP:
        {
            info.control_protocol = Sniffer::UDP;
            auto* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
            info.dst_port = udpLayer->getDstPort();
            info.src_port = udpLayer->getSrcPort();
        }
        break;

    case pcpp::ICMP:
        info.control_protocol = Sniffer::ICMP;
        break;
    
    default:
        info.control_protocol = Sniffer::UNK;
        break;
    }

    stats->push_back(info);

}

int Sniffer::start(){
    if (!(this->dev)->open())
    {
        std::cerr << "Cannot open device" << std::endl;
        return 1;
    }

    dev->startCapture(onPacketArrives, &packets);

    return 0;
}

void Sniffer::stop(){
    this->dev->stopCapture();
}

Sniffer::~Sniffer(){
    this->dev->stopCapture();
    delete[] dev;
    delete[] &packets;
}