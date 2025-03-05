
#ifndef __FILTER__
#define __FILTER__


#include <iostream>

class MQTT_client{

    private:

    char* chain;

    public:

    static const char* ACCEPT;
    static const char* DROP;

    MQTT_client();

    MQTT_client(char* chain);


    ~MQTT_client();

};


#endif
