#include "mqtt_client.h"
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

MQTT_client::MQTT_client(std::string device_id, std::string client_id, std::string username,std::string password, std::string address){ 
    this->device_id = device_id;
    this->client_id = client_id;
    this->username = username;
    this->password = password;
    this->address = address;
}



MQTT_client::~MQTT_client(){
    int status;
    while ((wait(&status)) > 0);
}