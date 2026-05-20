#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

using namespace std;

typedef struct ip_header {
    unsigned char  ihl:4;
    unsigned char  version:4;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
} ip_header;

int link_hdr_length = 14;

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
    // Saltar encabezado Ethernet
    pkt_data += link_hdr_length;

    // Interpretar bytes como encabezado IP
    ip_header* ip_hdr = (ip_header*)pkt_data;

    // Estructuras para IP origen y destino
    in_addr src, dst;

    src.s_addr = ip_hdr->saddr;
    dst.s_addr = ip_hdr->daddr;

    cout << "----------------------" << endl;
    cout << "Origen : " << inet_ntoa(src) << endl;
    cout << "Destino: " << inet_ntoa(dst) << endl;
    cout << "TTL    : " << (int)ip_hdr->ttl << endl;
    cout << "----------------------" << endl;
}

int main(){
    // Inicializar Winsock
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        cout << "Error al iniciar Winsock" << endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    // Obtener lista de interfaces
    pcap_if_t* alldevs;

    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        cout << "Error al obtener interfaces: " << errbuf << endl;
        return 1;
    }

    //abre interfaz wifi
    pcap_if_t* device = nullptr;
    for(pcap_if_t* d = alldevs; d; d = d->next){
        if(d->description){
            string desc = d->description;
            if(desc.find("Wi-Fi") != string::npos || desc.find("Wireless") != string::npos ||desc.find("802.11") != string::npos){
                device = d; 
                break;
            }
        }
    }

    if(device == nullptr){
        cout << "No se ha encontrado una interfaz wifi." <<endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }
    cout << "Interfaz utilizada: " << device->description << endl;
    pcap_t* handle = pcap_open_live(device->name, 65536,1,1000,errbuf);

    if(!handle){
        cout << "Error al abrir interfaz" << endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    cout << "Capturando 5 paquetes..." << endl;

    // Capturar 5 paquetes
    pcap_loop(handle, 5, packet_handler, NULL);

    // Liberar recursos
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    WSACleanup();

    return 0;
}