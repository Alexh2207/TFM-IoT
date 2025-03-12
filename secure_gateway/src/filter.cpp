#include "filter.h"
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

char command[10] = "iptables";
char add_chain_flag[4] = "-I";
char delete_chain_flag[4] = "-D";
char source_ip_flag[4] = "-s";
char dst_ip_flag[4] = "-d";
char proto_flag[4] = "-p";
char source_port_flag[8] = "--sport";
char dst_port_flag[8] = "--dport";
char action_flag[4] = "-j";

Filter::Filter(){
    strcpy(chain,std::string("FORWARD").c_str());
}

Filter::Filter(char* chain){ 
    this->chain = chain;
}

int Filter::manage_iptables_rule(Filter::rule rule){
    char src_ip_local[32];
    char dst_ip_local[32];
    char src_port_local[8];
    char dst_port_local[8];
    char proto_local[8];
    char action[8];
    strcpy(src_ip_local, rule.src_ip.c_str());
    strcpy(dst_ip_local, rule.dst_ip.c_str());
    strcpy(src_port_local, std::to_string(rule.src_port).c_str());
    strcpy(dst_port_local, std::to_string(rule.dst_port).c_str());
    strcpy(proto_local, rule.proto.c_str());
    strcpy(action,rule.action.c_str());
    pid_t pid = fork();
    int status;
    if (pid == 0)
    {
        if(rule.add == 1){
            char* argument_list[] = {command,add_chain_flag, chain, source_ip_flag, src_ip_local, dst_ip_flag, dst_ip_local, proto_flag, proto_local, source_port_flag, src_port_local, dst_port_flag, dst_port_local, action_flag, action,NULL};
            if(execvp("/usr/sbin/iptables",argument_list) == -1){
                exit(-1);
            }
        }
        else{
            char* argument_list[] = {command,delete_chain_flag, chain, source_ip_flag, src_ip_local, dst_ip_flag, dst_ip_local, proto_flag, proto_local, source_port_flag, src_port_local, dst_port_flag, dst_port_local, action_flag, action,NULL};
            if(execvp("/usr/sbin/iptables",argument_list) == -1){
                exit(-1);
            }
        }

    }else{
        waitpid(pid, &status,0);
    }

    return status;
}

Filter::~Filter(){
    int status;
    while ((wait(&status)) > 0);
}