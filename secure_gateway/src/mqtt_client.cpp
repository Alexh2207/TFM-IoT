#include "mqtt_client.h"
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>


MQTT_client::MQTT_client(){
    chain = "FORWARD";
}

MQTT_client::MQTT_client(char* chain){ 
    this->chain = chain;
}



MQTT_client::~MQTT_client(){
    int status;
    while ((wait(&status)) > 0);
}