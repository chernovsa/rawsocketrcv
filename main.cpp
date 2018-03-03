#include <iostream>
#include <thread>             // std::thread
#include <mutex>              // std::mutex, std::unique_lock
#include <condition_variable> // std::condition_variable

#include "snifferdatamanager.h"
#include "lpcapsocket.h"
#include "ubus_publish.h"
using namespace std;

void pcap_process_packet(char *keeper, int bytes)
{
    if (keeper)
    {
        SnifferDataManager *k= (SnifferDataManager*)keeper;
        k->onPacketReceived(bytes);
    }
}

int main(int argc,char **argv)
{
    enum {
        PCAP_THREAD,
        UBUS_THREAD,
        THREADS_SIZE
    };
    SnifferDataManager dataManager(0,0);
    sniffer_arg pcap_arg={&pcap_process_packet,(char*)&dataManager};
    std::thread threads[THREADS_SIZE];
    threads[PCAP_THREAD] = std::thread(start_pcap,&pcap_arg);

    for (auto& th : threads) th.join();


    //ubus_main(argc,argv);
    return 0;
}

