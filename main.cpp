#include <iostream>
#include "lpcapsocket.h"
#include "ubus_publish.h"
using namespace std;

int main(int argc,char **argv)
{
    //start_pcap();
    ubus_main(argc,argv);
    return 0;
}

