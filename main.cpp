#include <iostream>
#include <thread>             // std::thread
#include <mutex>              // std::mutex, std::unique_lock
#include <condition_variable> // std::condition_variable

//#include "lpcapsocket.h"
//#include "ubus_publish.h"
using namespace std;


std::mutex mtx;
std::condition_variable cv;
bool ready = false;


void print_id (int id) {
  std::unique_lock<std::mutex> lck(mtx);
  while (!ready) cv.wait(lck);
  // ...
  std::cout << "thread " << id << '\n';
}
void go() {
  std::unique_lock<std::mutex> lck(mtx);
  ready = true;
  cv.notify_all();
}

int main(int argc,char **argv)
{

    std::thread threads[10];
      // spawn 10 threads:
      for (int i=0; i<10; ++i)
         threads[i] = std::thread(print_id,i);

      std::cout << "10 threads ready to race...\n";
      go();                       // go!

      for (auto& th : threads) th.join();

    //start_pcap();
  //  ubus_main(argc,argv);
    return 0;
}

