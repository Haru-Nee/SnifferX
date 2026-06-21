#include <iostream>
#include <fstream>
#include <thread>
#include <stdlib.h>
#include <string>
#include <vector>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

using namespace std;

// Interfaz gráfica
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

// Ventana
#include <GLFW/glfw3.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

// ESTRUCTURAS

// Cabecera Ethernet
typedef struct cabecera_ethernet {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
} cabecera_ethernet;

// Cabecera IP
typedef struct cabecera_ip {
    unsigned char  ihl:4;
    unsigned char  version:4;
    unsigned char  tos;
    unsigned short largo_total;
    unsigned short id;
    unsigned short fragmento;
    unsigned char  ttl;
    unsigned char  protocolo;
    unsigned short checksum;
    unsigned int   ip_origen;
    unsigned int   ip_destino;
} cabecera_ip;

// Cabecera TCP
typedef struct cabecera_tcp {
    unsigned short puerto_origen;
    unsigned short puerto_destino;
    unsigned int   numero_secuencia;
    unsigned int   numero_ack;
    unsigned char  data_offset:4;
    unsigned char  reservado:3;
    unsigned char  flags;
    unsigned short ventana;
    unsigned short checksum;
    unsigned short puntero_urgente;
} cabecera_tcp;

// Cabecera UDP
typedef struct cabecera_udp {
    unsigned short puerto_origen;
    unsigned short puerto_destino;
    unsigned short largo;
    unsigned short checksum;
} cabecera_udp;

// Cabecera ICMP
typedef struct cabecera_icmp {
    unsigned char tipo;
    unsigned char codigo;
    unsigned short checksum;
} cabecera_icmp;

// Info de cada paquete (para tabla)
struct PaqueteInfo {
    int numero;
    string ip_origen;
    string ip_destino;
    int ttl;
    int largo;
    string protocolo;
    string hora;
};

// Paquete completo con todos los detalles
struct PaqueteDetallado {
    PaqueteInfo info_basica;
    
    // Ethernet
    string mac_origen;
    string mac_destino;
    string ethertype;
    
    // IP
    unsigned char version_ip;
    unsigned char ihl;
    unsigned char tos;
    unsigned short largo_total;
    unsigned short id_ip;
    unsigned short fragmento;
    string protocolo_detalle;
    
    // Capa de transporte
    int puerto_origen;
    int puerto_destino;
    string flags_tcp;
    unsigned int numero_secuencia;
    unsigned int numero_ack;
    unsigned short ventana;
    
    // ICMP
    unsigned char tipo_icmp;
    unsigned char codigo_icmp;
    
    // Datos RAW
    vector<unsigned char> datos_raw;
    int longitud_raw;
};

// VARIABLES GLOBALES

vector<PaqueteInfo> paquetes;
vector<PaqueteInfo> paquetes_filtrados;
vector<PaqueteDetallado> paquetes_detallados;
mutex mutexPaquetes;
bool capturando = false;
pcap_t* manejador = nullptr;
int largo_cabecera_enlace = 14;
int contador_paquetes = 0;
string interfaz_seleccionada = "";
vector<string> interfaces_disponibles;

// Variables del filtro
string filtro_actual = "";
bool filtro_activo = false;
char buffer_filtro[256] = "";

// Variables para paquete seleccionado
PaqueteDetallado paquete_seleccionado;
bool paquete_seleccionado_valido = false;
int indice_seleccionado = -1;

// FUNCIONES DEL SNIFFER

string obtenerHoraActual() {
    SYSTEMTIME hora;
    GetLocalTime(&hora);
    char buffer[100];
    sprintf_s(buffer, "%02d:%02d:%02d.%03d", hora.wHour, hora.wMinute, hora.wSecond, hora.wMilliseconds);
    return string(buffer);
}

string obtenerNombreProtocolo(unsigned char protocolo) {
    switch(protocolo) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "Otro";
    }
}

string macToString(const unsigned char* mac) {
    char buffer[18];
    sprintf_s(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(buffer);
}

string obtenerFlagsTCP(unsigned char flags) {
    string resultado;
    if (flags & 0x01) resultado += "FIN ";
    if (flags & 0x02) resultado += "SYN ";
    if (flags & 0x04) resultado += "RST ";
    if (flags & 0x08) resultado += "PSH ";
    if (flags & 0x10) resultado += "ACK ";
    if (flags & 0x20) resultado += "URG ";
    return resultado.empty() ? "Ninguno" : resultado;
}

string obtenerEtherType(unsigned short ethertype) {
    switch(ethertype) {
        case 0x0800: return "IPv4 (0x0800)";
        case 0x0806: return "ARP (0x0806)";
        case 0x86DD: return "IPv6 (0x86DD)";
        default: {
            char buffer[32];
            sprintf_s(buffer, "Desconocido (0x%04X)", ethertype);
            return string(buffer);
        }
    }
}

string toLower(const string& str) {
    string result = str;
    transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

bool cumpleFiltro(const PaqueteInfo& paquete, const string& filtro) {
    if (filtro.empty()) return true;
    
    string filtro_lower = toLower(filtro);
    
    istringstream iss(filtro_lower);
    vector<string> condiciones;
    string condicion;
    
    while (getline(iss, condicion, ' ')) {
        if (condicion == "and" || condicion == "or") {
            condiciones.push_back(condicion);
        } else if (!condicion.empty()) {
            condiciones.push_back(condicion);
        }
    }
    
    if (condiciones.empty()) return true;
    
    bool resultado = false;
    string operador = "or";
    
    for (size_t i = 0; i < condiciones.size(); i++) {
        const string& cond = condiciones[i];
        
        if (cond == "and" || cond == "or") {
            operador = cond;
            continue;
        }
        
        bool cumple_condicion = false;
        
        if (cond == "tcp") {
            cumple_condicion = (paquete.protocolo == "TCP");
        } else if (cond == "udp") {
            cumple_condicion = (paquete.protocolo == "UDP");
        } else if (cond == "icmp") {
            cumple_condicion = (paquete.protocolo == "ICMP");
        }
        else if (cond.find("ip.src==") == 0) {
            string ip_buscada = cond.substr(8);
            cumple_condicion = (toLower(paquete.ip_origen).find(ip_buscada) != string::npos);
        }
        else if (cond.find("src==") == 0) {
            string ip_buscada = cond.substr(5);
            cumple_condicion = (toLower(paquete.ip_origen).find(ip_buscada) != string::npos);
        }
        else if (cond.find("ip.dst==") == 0) {
            string ip_buscada = cond.substr(8);
            cumple_condicion = (toLower(paquete.ip_destino).find(ip_buscada) != string::npos);
        }
        else if (cond.find("dst==") == 0) {
            string ip_buscada = cond.substr(5);
            cumple_condicion = (toLower(paquete.ip_destino).find(ip_buscada) != string::npos);
        }
        else if (cond.find("ip.addr==") == 0) {
            string ip_buscada = cond.substr(9);
            cumple_condicion = (toLower(paquete.ip_origen).find(ip_buscada) != string::npos ||
                              toLower(paquete.ip_destino).find(ip_buscada) != string::npos);
        }
        else if (cond.find("host==") == 0) {
            string ip_buscada = cond.substr(6);
            cumple_condicion = (toLower(paquete.ip_origen).find(ip_buscada) != string::npos ||
                              toLower(paquete.ip_destino).find(ip_buscada) != string::npos);
        }
        else if (cond.find("ttl==") == 0) {
            try {
                int ttl_buscado = stoi(cond.substr(5));
                cumple_condicion = (paquete.ttl == ttl_buscado);
            } catch (...) {
                cumple_condicion = false;
            }
        }
        else if (cond.find("ttl<") == 0) {
            try {
                int ttl_buscado = stoi(cond.substr(4));
                cumple_condicion = (paquete.ttl < ttl_buscado);
            } catch (...) {
                cumple_condicion = false;
            }
        }
        else if (cond.find("ttl>") == 0) {
            try {
                int ttl_buscado = stoi(cond.substr(4));
                cumple_condicion = (paquete.ttl > ttl_buscado);
            } catch (...) {
                cumple_condicion = false;
            }
        }
        else {
            cumple_condicion = (toLower(paquete.ip_origen).find(cond) != string::npos ||
                              toLower(paquete.ip_destino).find(cond) != string::npos ||
                              toLower(paquete.protocolo).find(cond) != string::npos);
        }
        
        if (i == 0 || operador == "or") {
            resultado = resultado || cumple_condicion;
        } else if (operador == "and") {
            resultado = resultado && cumple_condicion;
        }
    }
    
    return resultado;
}

void actualizarFiltro() {
    lock_guard<mutex> lock(mutexPaquetes);
    paquetes_filtrados.clear();
    
    if (filtro_actual.empty()) {
        paquetes_filtrados = paquetes;
    } else {
        for (const auto& paquete : paquetes) {
            if (cumpleFiltro(paquete, filtro_actual)) {
                paquetes_filtrados.push_back(paquete);
            }
        }
    }
}

void procesarPaquete(u_char* parametro, const struct pcap_pkthdr* cabecera, const u_char* datos_paquete) {
    if (!capturando) return;
    
    // Parsear Ethernet
    cabecera_ethernet* eth = (cabecera_ethernet*)datos_paquete;
    string mac_dst = macToString(eth->dst_mac);
    string mac_src = macToString(eth->src_mac);
    unsigned short ethertype = ntohs(eth->ethertype);
    
    // Avanzar a IP (14 bytes de cabecera Ethernet estándar)
    const u_char* datos_ip = datos_paquete + 14;
    cabecera_ip* ip = (cabecera_ip*)datos_ip;
    
    // Calcular offset a capa de transporte
    int ip_header_len = (ip->ihl) * 4;
    const u_char* datos_transporte = datos_ip + ip_header_len;
    
    // Variables para capa de transporte
    int puerto_origen = 0;
    int puerto_destino = 0;
    string flags_tcp = "";
    unsigned int seq_num = 0;
    unsigned int ack_num = 0;
    unsigned short ventana = 0;
    string proto_detalle = "";
    unsigned char tipo_icmp = 0;
    unsigned char codigo_icmp = 0;
    
    // Parsear según protocolo
    if (ip->protocolo == 6) { // TCP
        cabecera_tcp* tcp = (cabecera_tcp*)datos_transporte;
        puerto_origen = ntohs(tcp->puerto_origen);
        puerto_destino = ntohs(tcp->puerto_destino);
        flags_tcp = obtenerFlagsTCP(tcp->flags);
        seq_num = ntohl(tcp->numero_secuencia);
        ack_num = ntohl(tcp->numero_ack);
        ventana = ntohs(tcp->ventana);
        proto_detalle = "TCP";
    } else if (ip->protocolo == 17) { // UDP
        cabecera_udp* udp = (cabecera_udp*)datos_transporte;
        puerto_origen = ntohs(udp->puerto_origen);
        puerto_destino = ntohs(udp->puerto_destino);
        proto_detalle = "UDP";
    } else if (ip->protocolo == 1) { // ICMP
        cabecera_icmp* icmp = (cabecera_icmp*)datos_transporte;
        tipo_icmp = icmp->tipo;
        codigo_icmp = icmp->codigo;
        puerto_origen = 0;
        puerto_destino = 0;
        proto_detalle = "ICMP";
    }
    
    // Datos RAW
    vector<unsigned char> raw_data(datos_paquete, datos_paquete + cabecera->len);
    
    in_addr origen, destino;
    origen.s_addr = ip->ip_origen;
    destino.s_addr = ip->ip_destino;
    
    // Crear info básica
    PaqueteInfo info;
    info.numero = ++contador_paquetes;
    info.ip_origen = inet_ntoa(origen);
    info.ip_destino = inet_ntoa(destino);
    info.ttl = ip->ttl;
    info.largo = ntohs(ip->largo_total);
    info.protocolo = obtenerNombreProtocolo(ip->protocolo);
    info.hora = obtenerHoraActual();
    
    // Crear paquete detallado
    PaqueteDetallado detalle;
    detalle.info_basica = info;
    detalle.mac_origen = mac_src;
    detalle.mac_destino = mac_dst;
    detalle.ethertype = obtenerEtherType(ethertype);
    detalle.version_ip = ip->version;
    detalle.ihl = ip->ihl;
    detalle.tos = ip->tos;
    detalle.largo_total = ntohs(ip->largo_total);
    detalle.id_ip = ntohs(ip->id);
    detalle.fragmento = ntohs(ip->fragmento);
    detalle.protocolo_detalle = proto_detalle;
    detalle.puerto_origen = puerto_origen;
    detalle.puerto_destino = puerto_destino;
    detalle.flags_tcp = flags_tcp;
    detalle.numero_secuencia = seq_num;
    detalle.numero_ack = ack_num;
    detalle.ventana = ventana;
    detalle.tipo_icmp = tipo_icmp;
    detalle.codigo_icmp = codigo_icmp;
    detalle.datos_raw = raw_data;
    detalle.longitud_raw = cabecera->len;
    
    lock_guard<mutex> lock(mutexPaquetes);
    paquetes.push_back(info);
    paquetes_detallados.push_back(detalle);
    
    if (paquetes.size() > 1000) {
        paquetes.erase(paquetes.begin());
        paquetes_detallados.erase(paquetes_detallados.begin());
    }
    
    // Actualizar filtro
    if (!filtro_actual.empty() && cumpleFiltro(info, filtro_actual)) {
        paquetes_filtrados.push_back(info);
    } else if (filtro_actual.empty()) {
        paquetes_filtrados = paquetes;
    }
}

bool cargarInterfaces() {
    char buffer_error[PCAP_ERRBUF_SIZE];
    pcap_if_t* todas;
    
    if (pcap_findalldevs(&todas, buffer_error) == -1) {
        cerr << "Error al obtener interfaces: " << buffer_error << endl;
        return false;
    }
    
    interfaces_disponibles.clear();
    
    for (pcap_if_t* d = todas; d; d = d->next) {
        if (d->description) {
            string desc = d->description;
            string nombre = d->name;
            interfaces_disponibles.push_back(desc + " (" + nombre + ")");
        } else if (d->name) {
            interfaces_disponibles.push_back(d->name);
        }
    }
    
    pcap_freealldevs(todas);
    
    if (!interfaces_disponibles.empty() && interfaz_seleccionada.empty()) {
        interfaz_seleccionada = interfaces_disponibles[0];
    }
    
    return !interfaces_disponibles.empty();
}

bool iniciarCaptura() {
    if (capturando) return false;
    
    char buffer_error[PCAP_ERRBUF_SIZE];
    pcap_if_t* todas;
    
    if (pcap_findalldevs(&todas, buffer_error) == -1) {
        cerr << "Error al obtener interfaces" << endl;
        return false;
    }
    
    pcap_if_t* seleccionada = nullptr;
    for (pcap_if_t* d = todas; d; d = d->next) {
        string desc = d->description ? d->description : d->name;
        string nombre_mostrar = desc + " (" + string(d->name) + ")";
        
        if (nombre_mostrar == interfaz_seleccionada || string(d->name) == interfaz_seleccionada) {
            seleccionada = d;
            break;
        }
    }
    
    if (!seleccionada) {
        pcap_freealldevs(todas);
        cerr << "No se encontró la interfaz seleccionada" << endl;
        return false;
    }
    
    manejador = pcap_open_live(seleccionada->name, 65536, 1, 1000, buffer_error);
    pcap_freealldevs(todas);
    
    if (!manejador) {
        cerr << "Error al abrir interfaz: " << buffer_error << endl;
        return false;
    }
    
    contador_paquetes = 0;
    capturando = true;
    
    thread hilo([]() {
        pcap_loop(manejador, 0, procesarPaquete, nullptr);
    });
    hilo.detach();
    
    return true;
}

void detenerCaptura() {
    if (!capturando) return;
    capturando = false;
    if (manejador) {
        pcap_breakloop(manejador);
        pcap_close(manejador);
        manejador = nullptr;
    }
}

void limpiarPaquetes() {
    lock_guard<mutex> lock(mutexPaquetes);
    paquetes.clear();
    paquetes_filtrados.clear();
    paquetes_detallados.clear();
    contador_paquetes = 0;
    paquete_seleccionado_valido = false;
    indice_seleccionado = -1;
}

void exportarCSV(){
    SYSTEMTIME st;
    GetLocalTime(&st);
    char nombre[100];
    sprintf_s(nombre, "captura_%04d%02d%02d_%02d%02d%02d.csv", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    ofstream archivo(nombre);
    if (!archivo.is_open()) {
        cerr << "Error al crear el archivo" << endl;
        return;
    }
    
    archivo << "Numero,Hora,IP Origen,IP Destino,Protocolo,TTL,Largo(bytes),MAC Origen,MAC Destino,Puerto Origen,Puerto Destino\n";

    lock_guard<mutex> lock(mutexPaquetes);
    
    const auto& paquetes_exportar = filtro_activo ? paquetes_filtrados : paquetes;
    
    for(const auto& aux : paquetes_exportar){
        archivo << aux.numero << "," << aux.hora << "," << aux.ip_origen << "," 
                << aux.ip_destino << "," << aux.protocolo << "," << aux.ttl 
                << "," << aux.largo << ",";
        
        for (const auto& detalle : paquetes_detallados) {
            if (detalle.info_basica.numero == aux.numero) {
                archivo << detalle.mac_origen << "," << detalle.mac_destino << ","
                       << detalle.puerto_origen << "," << detalle.puerto_destino;
                break;
            }
        }
        archivo << "\n";
    }
    archivo.close();
    cout << "Exportado a: " << nombre << endl;
}

// FUNCIONES DE LOS PANELES

void dibujarPanelDetallePaquete() {
    ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "INFORMACION ESTRUCTURADA DEL PAQUETE");
    ImGui::Separator();
    ImGui::Spacing();
    
    if (!paquete_seleccionado_valido) {
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Seleccione un paquete de la lista superior para ver sus detalles");
        return;
    }
    
    char buffer[256];
    
    // Frame
    sprintf_s(buffer, "Frame %d: %d bytes", paquete_seleccionado.info_basica.numero, paquete_seleccionado.longitud_raw);
    if (ImGui::TreeNode(buffer)) {
        ImGui::Text("Numero de paquete: %d", paquete_seleccionado.info_basica.numero);
        ImGui::Text("Hora de captura: %s", paquete_seleccionado.info_basica.hora.c_str());
        ImGui::Text("Longitud total: %d bytes", paquete_seleccionado.longitud_raw);
        ImGui::TreePop();
    }
    ImGui::Spacing();
    
    // Ethernet II
    if (ImGui::TreeNode("Ethernet II")) {
        ImGui::Text("MAC Destino: %s", paquete_seleccionado.mac_destino.c_str());
        ImGui::Text("MAC Origen:  %s", paquete_seleccionado.mac_origen.c_str());
        ImGui::Text("Tipo:       %s", paquete_seleccionado.ethertype.c_str());
        ImGui::TreePop();
    }
    ImGui::Spacing();
    
    // Internet Protocol Version 4
    if (ImGui::TreeNode("Internet Protocol Version 4")) {
        ImGui::Text("Version: %d", paquete_seleccionado.version_ip);
        ImGui::Text("IHL (Longitud cabecera): %d bytes (%d)", paquete_seleccionado.ihl * 4, paquete_seleccionado.ihl);
        ImGui::Text("TOS (Tipo de servicio): 0x%02X", paquete_seleccionado.tos);
        ImGui::Text("Longitud total: %d bytes", paquete_seleccionado.largo_total);
        ImGui::Text("Identificador: 0x%04X", paquete_seleccionado.id_ip);
        ImGui::Text("Fragmento: 0x%04X", paquete_seleccionado.fragmento);
        ImGui::Text("TTL (Time to Live): %d", paquete_seleccionado.info_basica.ttl);
        
        int proto_num = 0;
        if (paquete_seleccionado.info_basica.protocolo == "TCP") proto_num = 6;
        else if (paquete_seleccionado.info_basica.protocolo == "UDP") proto_num = 17;
        else if (paquete_seleccionado.info_basica.protocolo == "ICMP") proto_num = 1;
        
        ImGui::Text("Protocolo: %s (%d)", paquete_seleccionado.info_basica.protocolo.c_str(), proto_num);
        ImGui::Text("IP Origen: %s", paquete_seleccionado.info_basica.ip_origen.c_str());
        ImGui::Text("IP Destino: %s", paquete_seleccionado.info_basica.ip_destino.c_str());
        ImGui::TreePop();
    }
    ImGui::Spacing();
    
    // Capa de transporte
    if (paquete_seleccionado.info_basica.protocolo == "TCP") {
        if (ImGui::TreeNode("Transmission Control Protocol (TCP)")) {
            ImGui::Text("Puerto Origen: %d", paquete_seleccionado.puerto_origen);
            ImGui::Text("Puerto Destino: %d", paquete_seleccionado.puerto_destino);
            ImGui::Text("Numero de Secuencia: %u", paquete_seleccionado.numero_secuencia);
            ImGui::Text("Numero de ACK: %u", paquete_seleccionado.numero_ack);
            ImGui::Text("Ventana: %d", paquete_seleccionado.ventana);
            ImGui::Text("Flags: %s", paquete_seleccionado.flags_tcp.c_str());
            ImGui::TreePop();
        }
    } else if (paquete_seleccionado.info_basica.protocolo == "UDP") {
        if (ImGui::TreeNode("User Datagram Protocol (UDP)")) {
            ImGui::Text("Puerto Origen: %d", paquete_seleccionado.puerto_origen);
            ImGui::Text("Puerto Destino: %d", paquete_seleccionado.puerto_destino);
            ImGui::TreePop();
        }
    } else if (paquete_seleccionado.info_basica.protocolo == "ICMP") {
        if (ImGui::TreeNode("Internet Control Message Protocol (ICMP)")) {
            ImGui::Text("Tipo: %d", paquete_seleccionado.tipo_icmp);
            ImGui::Text("Codigo: %d", paquete_seleccionado.codigo_icmp);
            ImGui::TreePop();
        }
    }
}

void dibujarPanelDatosRaw() {
    ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "CONTENIDO RAW (HEXADECIMAL / ASCII)");
    ImGui::Separator();
    ImGui::Spacing();
    
    if (!paquete_seleccionado_valido) {
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Seleccione un paquete de la lista superior para ver su contenido RAW");
        return;
    }
    
    ImGui::Text("Tamano del paquete: %d bytes", paquete_seleccionado.longitud_raw);
    ImGui::Separator();
    ImGui::Spacing();
    
    ImGui::BeginChild("HexDump", ImVec2(0, 0), true);
    
    int bytes_por_linea = 16;
    const auto& datos = paquete_seleccionado.datos_raw;
    char offset[16];
    
    for (size_t i = 0; i < datos.size(); i += bytes_por_linea) {
        // Offset
        sprintf_s(offset, "%04X  ", (unsigned int)i);
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "%s", offset);
        ImGui::SameLine();
        
        // Bytes en hexadecimal
        string hex_line;
        string ascii_line;
        
        for (int j = 0; j < bytes_por_linea; j++) {
            if (i + j < datos.size()) {
                char hex[4];
                sprintf_s(hex, "%02X ", datos[i + j]);
                hex_line += hex;
                
                if (datos[i + j] >= 32 && datos[i + j] <= 126) {
                    ascii_line += (char)datos[i + j];
                } else {
                    ascii_line += ".";
                }
            } else {
                hex_line += "   ";
                ascii_line += " ";
            }
            
            if (j == 7) {
                hex_line += " ";
            }
        }
        
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.3f, 1.0f), "%s", hex_line.c_str());
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.3f, 0.8f, 0.3f, 1.0f), " |%s|", ascii_line.c_str());
    }
    
    ImGui::EndChild();
}

// INTERFAZ GRÁFICA

void dibujarInterfaz(GLFWwindow* ventana) {
    int ancho_ventana, alto_ventana;
    glfwGetFramebufferSize(ventana, &ancho_ventana, &alto_ventana);
    
    // Panel superior
    float alto_superior = 50.0f;
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(ancho_ventana, alto_superior));
    ImGui::Begin("BarraSuperior", nullptr, 
        ImGuiWindowFlags_NoTitleBar | 
        ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse);
    
    ImVec2 tamano_texto = ImGui::CalcTextSize("Sniffer de Red - Analizador de Paquetes");
    ImGui::SetCursorPosX((ancho_ventana - tamano_texto.x) * 0.5f);
    ImGui::SetCursorPosY(15);
    ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "Sniffer de Red - Analizador de Paquetes");
    
    ImGui::End();
    
    // Panel izquierdo
    float ancho_izquierdo = 280.0f;
    ImGui::SetNextWindowPos(ImVec2(0, alto_superior));
    ImGui::SetNextWindowSize(ImVec2(ancho_izquierdo, alto_ventana - alto_superior));
    ImGui::Begin("PanelControl", nullptr, 
        ImGuiWindowFlags_NoTitleBar | 
        ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar);
    
    ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "CONFIGURACION");
    ImGui::Separator();
    ImGui::Spacing();
    
    // Selector de interfaz
    ImGui::Text("Interfaz de red:");
    ImGui::PushItemWidth(-1);
    if (ImGui::BeginCombo("##interfaz", interfaz_seleccionada.c_str())) {
        for (const auto& iface : interfaces_disponibles) {
            bool seleccionada = (interfaz_seleccionada == iface);
            if (ImGui::Selectable(iface.c_str(), seleccionada)) {
                interfaz_seleccionada = iface;
            }
            if (seleccionada) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }
    ImGui::PopItemWidth();
    
    ImGui::Spacing();
    ImGui::Spacing();
    
    // Botones de control
    ImVec4 colorActivo = ImVec4(0.2f, 0.8f, 0.2f, 1.0f);
    ImVec4 colorParada = ImVec4(0.9f, 0.2f, 0.2f, 1.0f);
    
    ImGui::PushStyleColor(ImGuiCol_Button, capturando ? colorParada : colorActivo);
    
    if (capturando) {
        if (ImGui::Button("DETENER CAPTURA", ImVec2(-1, 45))) {
            detenerCaptura();
        }
    } else {
        if (ImGui::Button("INICIAR CAPTURA", ImVec2(-1, 45))) {
            if (cargarInterfaces() && !interfaz_seleccionada.empty()) {
                iniciarCaptura();
            }
        }
    }
    
    ImGui::PopStyleColor();
    ImGui::Spacing();
    
    if (ImGui::Button("LIMPIAR TABLA", ImVec2(-1, 40))) {
        limpiarPaquetes();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Sección de filtro
    ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "FILTRO");
    ImGui::Separator();
    ImGui::Spacing();
    
    ImGui::Text("Expresion de filtro:");
    ImGui::PushItemWidth(-1);
    
    if (ImGui::InputTextWithHint("##filtro", "Ej: tcp and ip.src==192.168.1.1", 
                                  buffer_filtro, sizeof(buffer_filtro),
                                  ImGuiInputTextFlags_EnterReturnsTrue)) {
        filtro_actual = buffer_filtro;
        filtro_activo = !filtro_actual.empty();
        actualizarFiltro();
    }
    ImGui::PopItemWidth();
    
    ImGui::Spacing();
    
    if (ImGui::Button("APLICAR FILTRO", ImVec2(-1, 35))) {
        filtro_actual = buffer_filtro;
        filtro_activo = !filtro_actual.empty();
        actualizarFiltro();
    }
    
    ImGui::Spacing();
    
    if (ImGui::Button("LIMPIAR FILTRO", ImVec2(-1, 30))) {
        buffer_filtro[0] = '\0';
        filtro_actual = "";
        filtro_activo = false;
        actualizarFiltro();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Estadísticas
    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "ESTADISTICAS");
    ImGui::Separator();
    ImGui::Spacing();
    
    ImGui::Text("Total capturados:");
    ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.2f, 1.0f), "    %d", (int)paquetes.size());
    
    ImGui::Text("Mostrados (filtro):");
    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "    %d", (int)paquetes_filtrados.size());
    
    ImGui::Spacing();
    ImGui::Text("Ultimo paquete:");
    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "    %s", paquetes.empty() ? "---" : paquetes.back().hora.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Indicador de estado
    if (capturando) {
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "● CAPTURANDO...");
    } else {
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "○ DETENIDO");
    }
    
    if (filtro_activo) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "▼ FILTRO ACTIVO");
        ImGui::TextWrapped("%s", filtro_actual.c_str());
    }
    
    ImGui::End();
    
    // =============================================
    // PANEL DERECHO DIVIDIDO EN 3 AREAS
    // =============================================
    
    float ancho_derecho = ancho_ventana - ancho_izquierdo;
    float alto_disponible = alto_ventana - alto_superior;
    
    // AREA 1: Tabla de paquetes (parte superior)
    float alto_area1 = alto_disponible * 0.45f;
    ImGui::SetNextWindowPos(ImVec2(ancho_izquierdo, alto_superior));
    ImGui::SetNextWindowSize(ImVec2(ancho_derecho, alto_area1));
    ImGui::Begin("Area1_TablaPaquetes", nullptr, 
        ImGuiWindowFlags_NoTitleBar | 
        ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove);
    
    if (filtro_activo) {
        ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "AREA 1: PAQUETES FILTRADOS");
    } else {
        ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "AREA 1: PAQUETES CAPTURADOS");
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), " (Mostrando %d de %d)", 
                      (int)paquetes_filtrados.size(), (int)paquetes.size());
    
    ImGui::Separator();
    ImGui::Spacing();
    
    // Botón exportar
    if (ImGui::Button("EXPORTAR A CSV", ImVec2(150, 30))) {
        exportarCSV();
    }
    ImGui::SameLine();
    
    if (filtro_activo) {
        ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "Filtro: %s", filtro_actual.c_str());
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    float altura_tabla = ImGui::GetContentRegionAvail().y;
    
    if (ImGui::BeginTable("Paquetes", 7, 
        ImGuiTableFlags_Borders | 
        ImGuiTableFlags_RowBg | 
        ImGuiTableFlags_Resizable | 
        ImGuiTableFlags_ScrollY, 
        ImVec2(0, altura_tabla))) {
        
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Hora", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Origen", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Destino", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("TTL", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableSetupColumn("Largo", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();
        
        lock_guard<mutex> lock(mutexPaquetes);
        
        for (const auto& pkt : paquetes_filtrados) {
            ImGui::TableNextRow();
            
            // Columna 0: Número (seleccionable)
            ImGui::TableSetColumnIndex(0);
            char label[32];
            sprintf_s(label, "%d", pkt.numero);
            
            if (ImGui::Selectable(label, indice_seleccionado == pkt.numero, 
                                 ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                indice_seleccionado = pkt.numero;
                for (const auto& detalle : paquetes_detallados) {
                    if (detalle.info_basica.numero == pkt.numero) {
                        paquete_seleccionado = detalle;
                        paquete_seleccionado_valido = true;
                        break;
                    }
                }
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s", pkt.hora.c_str());
            
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", pkt.ip_origen.c_str());
            
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%s", pkt.ip_destino.c_str());
            
            ImGui::TableSetColumnIndex(4);
            if (pkt.protocolo == "TCP") {
                ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "%s", pkt.protocolo.c_str());
            } else if (pkt.protocolo == "UDP") {
                ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.2f, 1.0f), "%s", pkt.protocolo.c_str());
            } else if (pkt.protocolo == "ICMP") {
                ImGui::TextColored(ImVec4(0.8f, 0.2f, 0.2f, 1.0f), "%s", pkt.protocolo.c_str());
            } else {
                ImGui::Text("%s", pkt.protocolo.c_str());
            }
            
            ImGui::TableSetColumnIndex(5);
            ImGui::Text("%d", pkt.ttl);
            
            ImGui::TableSetColumnIndex(6);
            ImGui::Text("%d", pkt.largo);
        }
        
        ImGui::EndTable();
    }
    
    ImGui::End();
    
    // AREA 2: Información estructurada del paquete seleccionado (parte media)
    float alto_area2 = alto_disponible * 0.27f;
    ImGui::SetNextWindowPos(ImVec2(ancho_izquierdo, alto_superior + alto_area1));
    ImGui::SetNextWindowSize(ImVec2(ancho_derecho, alto_area2));
    ImGui::Begin("Area2_DetallePaquete", nullptr, 
        ImGuiWindowFlags_NoTitleBar | 
        ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove);
    
    ImGui::BeginChild("ScrollDetalle", ImVec2(0, 0), true);
    dibujarPanelDetallePaquete();
    ImGui::EndChild();
    
    ImGui::End();
    
    // AREA 3: Contenido RAW en hexadecimal (parte inferior)
    float alto_area3 = alto_disponible * 0.28f;
    ImGui::SetNextWindowPos(ImVec2(ancho_izquierdo, alto_superior + alto_area1 + alto_area2));
    ImGui::SetNextWindowSize(ImVec2(ancho_derecho, alto_area3));
    ImGui::Begin("Area3_DatosRaw", nullptr, 
        ImGuiWindowFlags_NoTitleBar | 
        ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove);
    
    dibujarPanelDatosRaw();
    
    ImGui::End();
}

// Main
int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "Error al iniciar Winsock" << endl;
        return 1;
    }
    
    if (!cargarInterfaces()) {
        cerr << "No se encontraron interfaces de red" << endl;
        WSACleanup();
        return 1;
    }
    
    if (!glfwInit()) {
        cerr << "Error al iniciar GLFW" << endl;
        WSACleanup();
        return 1;
    }
    
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);
    
    GLFWwindow* ventana = glfwCreateWindow(1280, 720, "Sniffer", NULL, NULL);
    if (!ventana) {
        cerr << "Error al crear la ventana" << endl;
        glfwTerminate();
        WSACleanup();
        return 1;
    }
    
    glfwMakeContextCurrent(ventana);
    glfwSwapInterval(1);
    
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    
    ImGui::StyleColorsDark();
    
    ImGui_ImplGlfw_InitForOpenGL(ventana, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    
    paquetes_filtrados = paquetes;
    
    while (!glfwWindowShouldClose(ventana)) {
        glfwPollEvents();
        
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        
        dibujarInterfaz(ventana);
        
        ImGui::Render();
        int ancho, alto;
        glfwGetFramebufferSize(ventana, &ancho, &alto);
        glViewport(0, 0, ancho, alto);
        glClearColor(0.08f, 0.08f, 0.10f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        
        glfwSwapBuffers(ventana);
    }
    
    detenerCaptura();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(ventana);
    glfwTerminate();
    WSACleanup();
    
    return 0;
}