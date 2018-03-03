#include <iostream>
#include <thread>             // std::thread
#include <cstring>
#include "snifferdatamanager.h"
#include "lpcapsocket.h"
#include "ubus_publish.h"

void pcap_process_packet(char *keeper, int bytes)
{
    if (keeper)
    {
        SnifferDataManager *k= (SnifferDataManager*)keeper;
        k->onPacketReceived(bytes);
    }
}
void ubus_process_notify(char* keeper,SnifferData *data)
{
    if (keeper)
    {
        SnifferDataManager *k= (SnifferDataManager*)keeper;
        k->populateData(data);
    }
}

int main(int argc,char **argv)
{
    enum {
        IFNAME_PARAM,
        IP_PARAM,
        PORT_PARAM,
        TPERIOD_PARAM,
        PARAM_SIZE
    };
    char parameters[PARAM_SIZE][PARAM_STRING_SIZE];
    for(int i=0;i<PARAM_SIZE;i++)
        parameters[i][0]=0; //set strlen 0
    const char* keys[PARAM_STRING_SIZE]={"ifname=%s","ip=%s","port=%s","tperiod=%s"};
    int time_period=0;

    for(int i=1;i<argc;i++)
    {
        if (!strlen(parameters[IFNAME_PARAM]))
            sscanf(argv[i],keys[IFNAME_PARAM],parameters[IFNAME_PARAM]);

        if (!strlen(parameters[IP_PARAM]))
            sscanf(argv[i],keys[IP_PARAM],parameters[IP_PARAM]);

        if (!strlen(parameters[PORT_PARAM]))
            sscanf(argv[i],keys[PORT_PARAM],parameters[PORT_PARAM]);

        if (!strlen(parameters[TPERIOD_PARAM]))
            sscanf(argv[i],keys[TPERIOD_PARAM],parameters[TPERIOD_PARAM]);
    }
    int param_counter=0;
    for(int i=0;i<PARAM_SIZE;i++)
    {
        if (strlen(parameters[i]))
            param_counter++;
    }
    if (param_counter!=PARAM_SIZE  )
    {
        std::cerr<<"Please, input parametes :"<<std::endl;
        for(int i=0;i<PARAM_SIZE;i++)
            std::cerr<<keys[i]<<" ";
        std::cerr<<std::endl;
        return -1;
    }
    sscanf(parameters[TPERIOD_PARAM],"%d",&time_period);

    enum {
        PCAP_THREAD,
        UBUS_THREAD,
        THREADS_SIZE
    };
    SnifferDataManager dataManager(0,0);
    sniffer_arg pcap_arg={
        &pcap_process_packet,
        (char*)&dataManager,
        parameters[IFNAME_PARAM],
        parameters[IP_PARAM],
        parameters[PORT_PARAM]
    };

    ubus_sniffer_arg ubus_arg={&ubus_process_notify,(char*)&dataManager,time_period};
    std::thread threads[THREADS_SIZE];
    threads[PCAP_THREAD] = std::thread(start_pcap,&pcap_arg);
    threads[UBUS_THREAD] = std::thread(ubus_main,&ubus_arg);

    for (auto& th : threads) th.join();

    return 0;
}

