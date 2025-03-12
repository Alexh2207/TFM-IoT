
#ifndef __MQTT__
#define __MQTT__


#include <iostream>
#include "thread_queue.h"
#include "sniffer.h"
#include "filter.h"
#include <mqtt/async_client.h>
#include <json/json.h>

class MQTT_client{

    private:

    bool rpc_enabled;

    bool telemetry_enabled;

    std::string device_id;

    std::string client_id;

    std::string username;

    std::string password;

    std::string address;

    mqtt::async_client* client;

    std::thread telemetry_processor;

    void telemetry_sender();

    void RPC_received_callback(mqtt::const_message_ptr msg);

    void init();

    public:

    Thread_queue<Sniffer::PacketInfo> packet_q;
    Thread_queue<Filter::rule> rule_q;

    MQTT_client(std::string device_id, std::string client_id, std::string username,std::string password, std::string address);

    void enable_RPC();

    void disable_RPC();

    void enable_telemetry();

    void disable_telemetry();

    ~MQTT_client();

};


#endif
