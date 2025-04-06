#include "sniffer.h"
#include "filter.h"
#include "mqtt_client.h"

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
#include <mqtt/async_client.h>
#include <json/json.h>

//Time variables defined for MQTT
#define TIMEOUT 2
#define KEEPALIVE 500

#define MODULE 1

void telemetry_thread_orchestrator(std::reference_wrapper<MQTT_client> client, std::reference_wrapper<Sniffer> sniffer);

int main(int argc, char* argv[])
{

    MQTT_client cliente1 = MQTT_client("1234", "","tfmtest","tfmtest","127.0.0.1");

    cliente1.enable_telemetry();

    Sniffer sniffer1 = Sniffer("192.168.1.69");

    sniffer1.start();

    std::thread telemetry_thread_orch(telemetry_thread_orchestrator,std::ref(cliente1),std::ref(sniffer1));

    sleep(2);

    sniffer1.stop();

    telemetry_thread_orch.join();

    return 0;
}

void telemetry_thread_orchestrator(std::reference_wrapper<MQTT_client> client, std::reference_wrapper<Sniffer> sniffer){
    Sniffer::PacketInfo packet;

    while (sniffer.get().processed_packet_q.pop(2000,&packet) != -1)
    {
        std::cout << packet.dst_port << std::endl;
        client.get().packet_q.push(packet);
    }
    
}
