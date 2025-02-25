#include "filter.h"
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>


Filter::Filter(){
    chain = "FORWARD";
}

Filter::Filter(char* chain){ 
    this->chain = chain;
}

int Filter::add_iptables_rule(std::string src_ip, std::string dst_ip, std::string proto, int src_port, int dst_port, char* action){
    
    char src_ip_local[32];
    char dst_ip_local[32];
    char src_port_local[8];
    char dst_port_local[8];
    char proto_local[8];
    strcpy(src_ip_local, src_ip.c_str());
    strcpy(dst_ip_local, dst_ip.c_str());
    strcpy(src_port_local, std::to_string(src_port).c_str());
    strcpy(dst_port_local, std::to_string(dst_port).c_str());
    strcpy(proto_local, proto.c_str());
    pid_t pid = fork();
    int status;
    if (pid == 0)
    {
        char* argument_list[] = {"iptables","-I", chain, "-s", src_ip_local, "-d", dst_ip_local, "-p", proto_local, "--sport", src_port_local, "--dport", dst_port_local, "-j", action,NULL};
        if(execvp("/usr/sbin/iptables",argument_list) == -1){
            exit(-1);
        }
    }else{
        waitpid(pid, &status,0);
    }

    return status;
}

int Filter::delete_iptables_rule(std::string src_ip, std::string dst_ip, std::string proto, int src_port, int dst_port, char* action){
    char src_ip_local[32];
    char dst_ip_local[32];
    char src_port_local[8];
    char dst_port_local[8];
    char proto_local[8];
    strcpy(src_ip_local, src_ip.c_str());
    strcpy(dst_ip_local, dst_ip.c_str());
    strcpy(src_port_local, std::to_string(src_port).c_str());
    strcpy(dst_port_local, std::to_string(dst_port).c_str());
    strcpy(proto_local, proto.c_str());

    pid_t pid = fork();
    int status;
    if (pid == 0)
    {
        char* argument_list[] = {"iptables","-D", chain, "-s", src_ip_local, "-d", dst_ip_local, "-p", proto_local, "--sport", src_port_local, "--dport", dst_port_local, "-j", action,NULL};
        if(execvp("/usr/sbin/iptables",argument_list) == -1){
            exit(-1);
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