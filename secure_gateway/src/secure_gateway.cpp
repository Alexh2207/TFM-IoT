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
#include <mqtt/async_client.h>

//Time variables defined for MQTT
#define TIMEOUT 2
#define KEEPALIVE 500

#define MODULE 0

mqtt::async_client* client;

void message_callback(mqtt::const_message_ptr msg);

int main(int argc, char* argv[])
{
    if(MODULE == 0){

        std::string address = "127.0.0.1",device_id = "1234",
        client_name = "tfmtest";

        client = new mqtt::async_client(address, device_id);

        auto conOps = mqtt::connect_options_builder().user_name(client_name).password("tfmtest").connect_timeout(
                        std::chrono::seconds(TIMEOUT)).keep_alive_interval(
                        std::chrono::milliseconds(KEEPALIVE)).clean_session(true).finalize();

        client->set_message_callback(message_callback);

        if (client->connect(conOps)->wait_for(1000)) {
            std::cout << "Connected Successfully" << std::endl;
        } else {
            std::cerr << "Error in connection" << std::endl;
        }

        client->subscribe("v1/devices/me/rpc/request/+", 1);

        sleep(30);

        client->disconnect();

        delete client;
        
    }else{



    }

    return 0;
}

void message_callback(mqtt::const_message_ptr msg) {
	std::cout << "MSG_RECEIVED: " << msg->get_payload_str() << std::endl;
    std::cout << "RPC_ID: " << (msg->get_topic()).substr(26) << std::endl;

    if(msg->get_topic().find("request")>=0)
    {
        mqtt::message_ptr msg2 = mqtt::make_message("v1/devices/me/rpc/response/"+(msg->get_topic()).substr(26),"{\"changed\":true}");
        client->publish(msg2);

    }
}