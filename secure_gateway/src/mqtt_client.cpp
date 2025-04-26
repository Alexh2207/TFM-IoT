#include "mqtt_client.h"
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define TIMEOUT 2
#define KEEPALIVE 500

MQTT_client::MQTT_client(std::string device_id, std::string client_id, std::string username,std::string password, std::string address){ 
    this->device_id = device_id;
    this->client_id = client_id;
    this->username = username;
    this->password = password;
    this->address = address;
    this->telemetry_enabled = false;
    this->rpc_enabled = false;
    this->init();
}

void MQTT_client::init(){
    std::string address = "192.168.1.69",device_id = "1234",
    client_name = "tfmtest";

    this->client = new mqtt::async_client(address, device_id);

    auto conOps = mqtt::connect_options_builder().user_name(client_name).password("tfmtest").connect_timeout(
                    std::chrono::seconds(TIMEOUT)).keep_alive_interval(
                    std::chrono::milliseconds(KEEPALIVE)).clean_session(true).finalize();

    std::function<void(mqtt::const_message_ptr)> callback_RPC = [=](mqtt::const_message_ptr msg) {
        this->RPC_received_callback(msg);
    };
                    

    client->set_message_callback(callback_RPC);

    if (client->connect(conOps)->wait_for(1000)) {
        std::cout << "Connected Successfully" << std::endl;
    } else {
        std::cerr << "Error in connection" << std::endl;
    }
}

void MQTT_client::enable_RPC(){
    rpc_enabled = true;
    this->client->subscribe("v1/devices/me/rpc/request/+", 1);
}

void MQTT_client::disable_RPC(){
    rpc_enabled = false;
    this->client->unsubscribe("v1/devices/me/rpc/request/+");
}

void MQTT_client::enable_telemetry(){

    std::function<void()> telemetrySenderFunc = [=]() {
        this->telemetry_sender();
    };

    telemetry_enabled = true;

    telemetry_processor = std::thread(telemetrySenderFunc);

}

void MQTT_client::telemetry_sender() {

    Json::Value telemetry;
    Json::FastWriter writer;
    std::string message;

    while(telemetry_enabled){
        Sniffer::PacketInfo packet;
        
        if(packet_q.pop(200,&packet) >= 0){

            telemetry["size"] = packet.packet_size;
            telemetry["src_ip"] = packet.src_ip.toString();
            telemetry["dst_ip"] = packet.dst_ip.toString();
            telemetry["src_port"] = packet.src_port;
            telemetry["dst_port"] = packet.dst_port;
            telemetry["proto"] = packet.control_protocol;

            message = writer.write(telemetry);

            this->client->publish("v1/devices/me/telemetry",message);
        }
        
        
    }

}

void MQTT_client::disable_telemetry(){

    telemetry_enabled = false;

}

void MQTT_client::RPC_received_callback(mqtt::const_message_ptr msg) {
	std::cout << "MSG_RECEIVED: " << msg->get_payload_str() << std::endl;
    std::cout << "RPC_ID: " << (msg->get_topic()).substr(26) << std::endl;


    if(msg->get_topic().find("v1/devices/me/rpc/request") != std::string::npos){

        Json::Value root;

        Json::Reader reader;

        reader.parse(msg->get_payload_str(),root);

        std::cout << "METHOD: " << root["method"].asString() << std::endl;
        std::cout << "PROTO: " << root["params"]["proto"].asString() << std::endl;

        int add_rule = 0;

        if(root["method"].asString() == "rule_add")
            add_rule = 1;

        Filter::rule rule_add = {root["params"]["src_ip"].asString(),root["params"]["dst_ip"].asString(),root["params"]["proto"].asString(),root["params"]["src_port"].asInt(),root["params"]["dst_port"].asInt(),root["params"]["action"].asString(), add_rule};

        this->rule_q.push(rule_add);

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
    }else if (msg->get_topic().find("v1/devices/me/attributes/response") != std::string::npos){
        std::cout << "got attribute" << std::endl;
        this->int_rule_q.push(msg->get_payload_str());
    }
}

std::map<int,Filter::rule> MQTT_client::get_applied_rules(){
    this->client->publish("v1/devices/me/attributes/request/1","{\"clientKeys\":\"rule_array_client\"}");
    std::map<int,Filter::rule> rules;

    std::string json_answer;

    if(this->int_rule_q.pop(2000,&json_answer) != -1){
        Json::Value root;
        Json::Reader reader;

        reader.parse(json_answer, root);

        for(Json::Value rule : root["client"]["rule_array_client"]["rules"]){

            std::cout << rule["src_ip"].asString() << std::endl;
            Filter::rule rule_to_add = {rule["src_ip"].asString(),rule["dst_ip"].asString(),rule["proto"].asString(),rule["src_port"].asInt(),rule["dst_port"].asInt(),rule["action"].asString(), 0};
            rules.insert({rule["ruleID"].asInt(),rule_to_add});
        }
        
    }
    return rules;
}

void MQTT_client::update_applied_rules(std::map<int,Filter::rule> rules_applied){
    Json::Value rule_array_client;
    Json::Value rules;
    Json::Value rule_array;
    Json::FastWriter writer;
    std::string message;
    for (auto const& [key, val] : rules_applied)
    {
        Json::Value indiv_rule;
        indiv_rule["ruleID"] = key;
        indiv_rule["src_ip"] = val.src_ip;
        indiv_rule["dst_ip"] = val.dst_ip;
        indiv_rule["proto"] = val.proto;
        indiv_rule["src_port"] = val.src_port;
        indiv_rule["dst_port"] = val.dst_port;
        indiv_rule["action"] = val.action;

        std::cout << "rule " << key << " added" << std::endl;

        rule_array.append(indiv_rule);
    }
    rules["rules"] = rule_array;
    rule_array_client["rule_array_client"] = rules;

    message = writer.write(rule_array_client);

    this->client->publish("v1/devices/me/attributes",message);
}

MQTT_client::~MQTT_client(){

    disable_RPC();
    disable_telemetry();

    telemetry_processor.join();
    if(this->client->is_connected())
        this->client->disconnect();
    delete client;
}