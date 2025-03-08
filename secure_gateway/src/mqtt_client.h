
#ifndef __MQTT__
#define __MQTT__


#include <iostream>
#include "thread_queue.h"
#include "sniffer.h"
#include "filter.h"
#include <mqtt/async_client.h>

class MQTT_client{

    private:

    std::string device_id;

    std::string client_id;

    std::string username;

    std::string password;

    std::string address;

    public:

    Thread_queue<Sniffer::PacketInfo> packet_q;
    Thread_queue<Filter::rule> rules_q;

    MQTT_client(std::string device_id, std::string client_id, std::string username,std::string password, std::string address);


    ~MQTT_client();

};


#endif
