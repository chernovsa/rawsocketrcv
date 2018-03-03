#include "snifferdatamanager.h"
#include <iostream>
SnifferDataManager::SnifferDataManager(int packets, int bytes):mPackets(packets),mBytes(bytes){}

void SnifferDataManager::onPacketReceived(int bytes){
    std::unique_lock<std::mutex> lck(mtx);
    mBytes+=bytes;
    mPackets++;
#ifdef DEBUG_OUT
    std::cout<<"onPacketReceived "
            <<" bytes="
           <<bytes
          <<" total"
         <<" packets="
        <<mPackets
       <<" bytes="
      <<mBytes<<std::endl;
#endif
}

void SnifferDataManager::populateData(SnifferData *data){
    std::unique_lock<std::mutex> lck(mtx);
    if (data)
    {
    data->packets=mPackets;
    data->bytes=mBytes;
    }
#ifdef DEBUG_OUT
    std::cout<<"populateData "
            <<std::endl;
#endif
}
