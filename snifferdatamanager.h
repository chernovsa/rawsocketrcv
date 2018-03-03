#ifndef SNIFFERDATAMANAGER_H
#define SNIFFERDATAMANAGER_H
#include <mutex>              // std::mutex, std::unique_lock
#include "modules/ubus/ubustypes.h"
class SnifferDataManager{
public:
    SnifferDataManager(int packets,int bytes);
    void onPacketReceived(int bytes);
    void populateData(SnifferData *data);
private:
    void lockOnRecieved();
private:
    uint64_t mPackets;
    uint64_t mBytes;

    std::mutex mtx;
};

#endif // SNIFFERDATAMANAGER_H
