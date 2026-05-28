#include <iostream>
#include <fstream>
#include <thread>
#include <stdlib.h>
#include <string>
#include <vector>
#include <mutex>
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

// Info de cada paquete
struct PaqueteInfo {
    int numero;
    string ip_origen;
    string ip_destino;
    int ttl;
    int largo;
    string protocolo;
    string hora;
};

// VARIABLES GLOBALES

vector<PaqueteInfo> paquetes;
mutex mutexPaquetes;
bool capturando = false;
pcap_t* manejador = nullptr;
int largo_cabecera_enlace = 14;
int contador_paquetes = 0;
string interfaz_seleccionada = "";
vector<string> interfaces_disponibles;


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

void procesarPaquete(u_char* parametro, const struct pcap_pkthdr* cabecera, const u_char* datos_paquete) {
    if (!capturando) return;
    
    datos_paquete += largo_cabecera_enlace;
    cabecera_ip* ip = (cabecera_ip*)datos_paquete;
    
    in_addr origen, destino;
    origen.s_addr = ip->ip_origen;
    destino.s_addr = ip->ip_destino;
    
    PaqueteInfo info;
    info.numero = ++contador_paquetes;
    info.ip_origen = inet_ntoa(origen);
    info.ip_destino = inet_ntoa(destino);
    info.ttl = ip->ttl;
    info.largo = ntohs(ip->largo_total);
    info.protocolo = obtenerNombreProtocolo(ip->protocolo);
    info.hora = obtenerHoraActual();
    
    lock_guard<mutex> lock(mutexPaquetes);
    paquetes.push_back(info);
    
    if (paquetes.size() > 1000) {
        paquetes.erase(paquetes.begin());
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
    contador_paquetes = 0;
}

void exportarCSV(){
    //Generar el nombre del archivo con fecha y hora
    SYSTEMTIME st;
    GetLocalTime(&st);
    char nombre[100];
    sprintf_s(nombre, "captura_%04d%02d%02d_%02d%02d%02d.csv", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    //Abrir el archivo
    ofstream archivo(nombre);
    if (!archivo.is_open()) {
        cerr << "Error al crear el archivo" << endl;
        return;
    }
    // Escribir informacion del archivo
    archivo << "Numero,Hora,IP Origen,IP Destino,Protocolo,TTL,Largo(bytes)\n";

    //Escribir todos los paquetes
    lock_guard<mutex> lock(mutexPaquetes);
    for(const auto& aux : paquetes){
        archivo << aux.numero << "," << aux.hora << "," << aux.ip_origen << "," << aux.ip_destino << "," << aux.protocolo << "," << aux.ttl << "," << aux.largo << "\n";
    }
    archivo.close();
    cout<<"Exportado a: "<< nombre << endl;
}

// INTERFAZ GRÁFICA - PANTALLA COMPLETA

void dibujarInterfaz(GLFWwindow* ventana) {
    // Obtener tamaño de la ventana
    int ancho_ventana, alto_ventana;
    glfwGetFramebufferSize(ventana, &ancho_ventana, &alto_ventana);
    
    // Panel superior (barra de título personalizada)
    float alto_superior = 50.0f;
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(ancho_ventana, alto_superior));
    ImGui::Begin("BarraSuperior", nullptr, 
        ImGuiWindowFlags_NoTitleBar | 
        ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse);
    
    // Título centrado
    ImVec2 tamano_texto = ImGui::CalcTextSize("Sniffer de Red - Analizador de Paquetes");
    ImGui::SetCursorPosX((ancho_ventana - tamano_texto.x) * 0.5f);
    ImGui::SetCursorPosY(15);
    ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "Sniffer de Red - Analizador de Paquetes");
    
    ImGui::End();
    
    // Panel izquierdo (controles)
    float ancho_izquierdo = 280.0f;
    ImGui::SetNextWindowPos(ImVec2(0, alto_superior));
    ImGui::SetNextWindowSize(ImVec2(ancho_izquierdo, alto_ventana - alto_superior));
    ImGui::Begin("PanelControl", nullptr, 
        ImGuiWindowFlags_NoTitleBar | 
        ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar);
    
    ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "CONFIGURACIÓN");
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
    
    // Estadísticas
    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "ESTADÍSTICAS");
    ImGui::Separator();
    ImGui::Spacing();
    
    ImGui::Text("Paquetes capturados:");
    ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.2f, 1.0f), "    %d", (int)paquetes.size());
    
    ImGui::Spacing();
    ImGui::Text("Último paquete:");
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
    
    ImGui::End();
    
    // Panel derecho (tabla de paquetes)
    ImGui::SetNextWindowPos(ImVec2(ancho_izquierdo, alto_superior));
    ImGui::SetNextWindowSize(ImVec2(ancho_ventana - ancho_izquierdo, alto_ventana - alto_superior));
    ImGui::Begin("TablaPaquetes", nullptr, 
        ImGuiWindowFlags_NoTitleBar | 
        ImGuiWindowFlags_NoResize | 
        ImGuiWindowFlags_NoMove);
    
    ImGui::TextColored(ImVec4(0.2f, 0.6f, 1.0f, 1.0f), "PAQUETES CAPTURADOS");
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("EXPORTAR A CSV", ImVec2(150, 35))) {
        exportarCSV();
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    
    // Configurar tabla que ocupa todo el espacio disponible
    float altura_tabla = ImGui::GetContentRegionAvail().y;
    
    if (ImGui::BeginTable("Paquetes", 6, 
        ImGuiTableFlags_Borders | 
        ImGuiTableFlags_RowBg | 
        ImGuiTableFlags_Resizable | 
        ImGuiTableFlags_ScrollY, 
        ImVec2(0, altura_tabla))) {
        
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupColumn("Hora", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Origen", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Destino", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Protocolo", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("TTL", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableHeadersRow();
        
        lock_guard<mutex> lock(mutexPaquetes);
        
        for (const auto& pkt : paquetes) {
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%d", pkt.numero);
            
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
        }
        
        ImGui::EndTable();
    }
    
    ImGui::End();
}

// Main del programa

int main() {
    // Inicializar Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "Error al iniciar Winsock" << endl;
        return 1;
    }
    
    // Cargar interfaces
    if (!cargarInterfaces()) {
        cerr << "No se encontraron interfaces de red" << endl;
        WSACleanup();
        return 1;
    }
    
    // Iniciar GLFW
    if (!glfwInit()) {
        cerr << "Error al iniciar GLFW" << endl;
        WSACleanup();
        return 1;
    }
    
    // Configurar ventana
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);  // Inicia maximizada
    
    // Crear ventana (pantalla completa)
    GLFWwindow* ventana = glfwCreateWindow(1280, 720, "Sniffer", NULL, NULL);
    if (!ventana) {
        cerr << "Error al crear la ventana" << endl;
        glfwTerminate();
        WSACleanup();
        return 1;
    }
    
    glfwMakeContextCurrent(ventana);
    glfwSwapInterval(1);
    
    // Inicializar ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    
    // Estilo
    ImGui::StyleColorsDark();
    
    // Configurar backends
    ImGui_ImplGlfw_InitForOpenGL(ventana, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    
    // Bucle principal
    while (!glfwWindowShouldClose(ventana)) {
        glfwPollEvents();
        
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        
        // Dibujar interfaz
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