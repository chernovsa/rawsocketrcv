#include "lpcapsocket.h"
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

#define UNUSED(x) (void)(x)
void pcap_process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int get_udp_payload_size(const u_char * );
void process_ip_packet(const u_char * , int);
void print_udp_packet(const u_char * , int);
void PrintData (const u_char * , int);

FILE *logfile;
struct sockaddr_in source,dest;

int start_pcap(sniffer_arg *processArg)
{
    pcap_if_t *alldevsp , *device;
    pcap_t *handle; //Handle of the device that shall be sniffed

    char *devname , devs[100][100];
    int count = 1 , n;

    char errbuf[PCAP_ERRBUF_SIZE];
    char src_host[PARAM_STRING_SIZE];
    char udp_port[PARAM_STRING_SIZE];

    char filter_format[]="udp src port %s and src host %s and not icmp";
    char filter_string[1000];

    struct bpf_program filter;
    // Скомпилированное выражение для фильтра

    // Выражение для фильтра

    bpf_u_int32 mask;
    // Сетевая маска нашего интерфейса

    bpf_u_int32 net;
    // IP адрес нашего интерфейса

    //First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }
    printf("Done");

    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            if (!strcmp(device->name,processArg->ifname))
                n=count;
            strcpy(devs[count] , device->name);
        }
        count++;
    }

    //Ask user which device to sniff
    //printf("Enter the number of the device you want to sniff : ");
    //scanf("%d" , &n);
    devname = devs[n];

    /****set pcap filter*************/
    // Строка с ошибкой


    pcap_lookupnet(devname, &net, &mask, errbuf);
    //Open the device for sniffing
    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    printf("Done\n");

    logfile=fopen("log.txt","w");
    if(logfile==NULL)
    {
        printf("Unable to create file.");
    }

    strcpy(src_host,processArg->src_ipaddr);
    strcpy(udp_port,processArg->src_port);


    sprintf(filter_string,filter_format,udp_port,src_host);
    printf("get filter string \'%s\'\n",filter_string);

    if (pcap_compile(handle, &filter, filter_string, 0, net)!=0)
    {
        fprintf(stderr, "Couldn't compile filter  %s, error: %s \n"  , filter_string,pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &filter)!=0)
    {
        fprintf(stderr, "Couldn't set filter  %s, error: %s \n"  , filter_string,pcap_geterr(handle));
        exit(1);
    }
    /*****************************************/


    //Put the device in sniff loop
    return pcap_loop(handle , -1 , pcap_process_packet , (u_char*)processArg);

}

void pcap_process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    UNUSED(header);
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 17: //UDP Protocol
    {
            int bytes=get_udp_payload_size(buffer);
            if (args)
            {
            sniffer_arg* processArg=(sniffer_arg*)args;
            (*processArg->handler)(processArg->instance,bytes);
            }
//            print_udp_packet(buffer , size);
    }
            break;
    }
}

void print_ethernet_header(const u_char *Buffer)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer)
{
    print_ethernet_header(Buffer);

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

int get_udp_payload_size(const u_char *Buffer)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int udp_payload_len=ntohs(udph->len)-sizeof(udphdr);
    return udp_payload_len;
}

void print_udp_packet(const u_char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer);

    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);

    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile , "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);

    fprintf(logfile , "\n###########################################################");
}

void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        }

        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(logfile , "   "); //extra spaces
            }

            fprintf(logfile , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }

            fprintf(logfile ,  "\n" );
        }
    }
}
