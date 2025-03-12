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
        MQTT_client cliente1 = MQTT_client("1234", "","tfmtest","tfmtest","127.0.0.1");

        cliente1.enable_telemetry();

        sleep(1);

        cliente1.packet_q.push({100,pcpp::IPAddress("10.0.0.1"),pcpp::IPAddress("10.0.0.1"),Sniffer::ctrl_prot::TCP,80,80});

        sleep(2);

        cliente1.disable_telemetry();

    }

    return 0;
}

void message_callback(mqtt::const_message_ptr msg) {
	std::cout << "MSG_RECEIVED: " << msg->get_payload_str() << std::endl;
    std::cout << "RPC_ID: " << (msg->get_topic()).substr(26) << std::endl;

    Json::Value root;

    Json::Reader reader;

    reader.parse(msg->get_payload_str(),root);

    std::cout << "METHOD: " << root["method"].asString() << std::endl;
    std::cout << "PROTO: " << root["params"]["proto"].asString() << std::endl;

    int add_rule = 0;

    if(root["method"].asString() == "rule_add")
        add_rule = 1;

    Filter::rule rule_add = {root["params"]["src_ip"].asString(),root["params"]["dst_ip"].asString(),root["params"]["proto"].asString(),root["params"]["src_port"].asInt(),root["params"]["dst_port"].asInt(),root["params"]["action"].asString(), add_rule};

    MQTT_client client_q = MQTT_client("1234", "","tfmtest","tfmtest","127.0.0.1");

    client_q.rule_q.push(rule_add);

    if(msg->get_topic().find("request")>=0)
    {
        if(add_rule){
            mqtt::message_ptr msg2 = mqtt::make_message("v1/devices/me/rpc/response/"+(msg->get_topic()).substr(26),"{\"added\":true}");
            client->publish(msg2);
        }else{
            mqtt::message_ptr msg2 = mqtt::make_message("v1/devices/me/rpc/response/"+(msg->get_topic()).substr(26),"{\"deleted\":true}");
            client->publish(msg2);
        }

    }
}