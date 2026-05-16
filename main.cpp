#include <windows.h>
#include <devguid.h>
#include <setupapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <fstream> // Añadido para manejo de archivo de configuración

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

struct MandoInfo {
    std::wstring name;
    std::wstring hwID;
};

struct ProcesoInfo {
    DWORD pid;
    std::wstring nombre;
};

std::vector<std::wstring> g_bloqueados;
std::vector<DWORD> g_whitelistPIDs;
std::wstring g_exeTarget = L""; // Guarda el nombre del ejecutable de la configuración

const std::string CONFIG_FILE = "MandoShield.cfg";

// --- FUNCIONES DE PROCESOS ---

std::vector<ProcesoInfo> ListarProcesosUsuario() {
    std::vector<ProcesoInfo> lista;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID > 400) { 
                    lista.push_back({ pe.th32ProcessID, pe.szExeFile });
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    std::sort(lista.begin(), lista.end(), [](const ProcesoInfo& a, const ProcesoInfo& b) {
        return a.nombre < b.nombre;
    });
    return lista;
}

// Busca el PID en tiempo real de un ejecutable por su nombre (.exe)
DWORD ObtenerPIDPorNombre(const std::wstring& nombreExe) {
    if (nombreExe.empty()) return 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, nombreExe.c_str()) == 0) {
                    CloseHandle(hSnap);
                    return pe.th32ProcessID;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return 0;
}

// --- GESTIÓN DE CONFIGURACIÓN (.CFG) ---

void GuardarConfiguracionArchivo() {
    std::wofstream archivo(CONFIG_FILE);
    if (archivo.is_open()) {
        archivo << g_exeTarget << L"\n";
        for (const auto& id : g_bloqueados) {
            archivo << id << L"\n";
        }
        archivo.close();
    }
}

bool CargarConfiguracionArchivo() {
    std::wifstream archivo(CONFIG_FILE);
    if (!archivo.is_open()) return false;

    g_bloqueados.clear();
    if (std::getline(archivo, g_exeTarget)) {
        std::wstring linea;
        while (std::getline(archivo, linea)) {
            if (!linea.empty()) {
                g_bloqueados.push_back(linea);
            }
        }
        archivo.close();
        return true;
    }
    archivo.close();
    return false;
}

// --- GESTIÓN DE REGISTRO ---

bool AplicarCambios() {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) return false;

    // 1. AffectedDevices (Multi-SZ)
    std::vector<wchar_t> multiSz;
    for (const auto& id : g_bloqueados) {
        for (wchar_t c : id) multiSz.push_back(c);
        multiSz.push_back(L'\0');
    }
    multiSz.push_back(L'\0'); // Doble nulo final
    RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)multiSz.data(), (DWORD)(multiSz.size() * sizeof(wchar_t)));

    // 2. Limpiar Whitelist antigua (opcional)
    HKEY hKeyWhitelist;
    if (RegOpenKeyExW(hKey, L"Whitelist", 0, KEY_ALL_ACCESS, &hKeyWhitelist) == ERROR_SUCCESS) {
        wchar_t subKeyName[256];
        DWORD nameSize = 256;
        while (RegEnumKeyExW(hKeyWhitelist, 0, subKeyName, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            RegDeleteKeyW(hKeyWhitelist, subKeyName);
            nameSize = 256;
        }
        RegCloseKey(hKeyWhitelist);
    }

    // 3. Escribir Whitelist nueva (incluyendo el PID propio)
    std::vector<DWORD> pidsTemp = g_whitelistPIDs;
    pidsTemp.push_back(GetCurrentProcessId());

    for (DWORD pid : pidsTemp) {
        std::wstring p = L"Whitelist\\" + std::to_wstring(pid);
        HKEY hSubKey;
        if (RegCreateKeyExW(hKey, p.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hSubKey, NULL) == ERROR_SUCCESS) {
            RegCloseKey(hSubKey);
        }
    }
    RegCloseKey(hKey);
    return true;
}

void ReiniciarHID() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_HIDCLASS, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        SP_PROPCHANGE_PARAMS pcp = { {sizeof(SP_CLASSINSTALL_HEADER), DIF_PROPERTYCHANGE}, DICS_PROPCHANGE, DICS_FLAG_GLOBAL, 0 };
        if (SetupDiSetClassInstallParamsW(hDevInfo, &devData, &pcp.ClassInstallHeader, sizeof(pcp))) {
            SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devData);
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
}

std::vector<MandoInfo> ListarMandos() {
    std::vector<MandoInfo> lista;
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_HIDCLASS, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return lista;

    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        wchar_t buf[1024];
        MandoInfo m;
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)buf, sizeof(buf), NULL) ||
            SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_DEVICEDESC, NULL, (PBYTE)buf, sizeof(buf), NULL)) {
            m.name = buf;
        } else {
            m.name = L"Dispositivo desconocido";
        }
        
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_HARDWAREID, NULL, (PBYTE)buf, sizeof(buf), NULL)) {
            m.hwID = buf; 
            if (m.hwID.find(L"VID_") != std::wstring::npos) {
                lista.push_back(m);
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return lista;
}

// --- MAIN ---

int main() {
    _wsetlocale(LC_ALL, L"");
    bool usarConfigPrevia = false;

    // COMPROBACIÓN INICIAL DEL ARCHIVO .CFG
    if (CargarConfiguracionArchivo()) {
        std::wcout << L"==================================================\n";
        std::wcout << L"[*] SE DETECTO UNA CONFIGURACION PREVIA:\n";
        std::wcout << L"    - Ejecutable Whitelist: " << g_exeTarget << L"\n";
        std::wcout << L"    - Cantidad de mandos en plantilla: " << g_bloqueados.size() << L"\n";
        std::wcout << L"==================================================\n";
        std::wcout << L"[0] Mantener y aplicar configuracion previa\n";
        std::wcout << L"[1] Configurar de nuevo (Asistente manual)\n";
        std::wcout << L"Seleccion: ";
        
        int opcion;
        if (std::wcin >> opcion && opcion == 0) {
            usarConfigPrevia = true;
        }
        std::wcin.clear();
        std::wcin.ignore(10000, L'\n');
    }

    if (usarConfigPrevia) {
        // Buscar el PID actual en ejecución del ejecutable que estaba guardado
        DWORD pidActual = ObtenerPIDPorNombre(g_exeTarget);
        if (pidActual != 0) {
            g_whitelistPIDs.push_back(pidActual);
            std::wcout << L"\n[OK] Enlazado automaticamente a " << g_exeTarget << L" (PID: " << pidActual << L")\n";
        } else {
            std::wcout << L"\n[!] AVISO: " << g_exeTarget << L" no esta abierto ahora mismo.\n";
            std::wcout << L"    La whitelist se aplicara dinamicamente cuando lo abras.\n";
        }
        Sleep(1500);

        // Aplicamos directo lo cargado del archivo al registro y refrescamos el driver
        AplicarCambios();
        ReiniciarHID();
    } 
    else {
        // PASO 1 TRADICIONAL (Solo si no hay archivo o si se presionó 1)
        system("cls");
        auto procesos = ListarProcesosUsuario();
        std::wcout << L"=== PASO 1: SELECCIONAR PROGRAMA PARA WHITELIST ===\n";
        std::wcout << L"Lista de procesos activos (Usuario):\n";
        
        for (size_t i = 0; i < procesos.size(); i++) {
            std::wcout << (i + 1) << L". " << procesos[i].nombre << L"\t";
            if ((i + 1) % 3 == 0) std::wcout << L"\n";
        }
        
        std::wcout << L"\n\nIngrese el NUMERO del proceso a autorizar (0 para omitir): ";
        int selP;
        if (!(std::wcin >> selP)) {
            std::wcin.clear();
            std::wcin.ignore(10000, L'\n');
            selP = 0;
        }

        if (selP > 0 && selP <= (int)procesos.size()) {
            g_whitelistPIDs.push_back(procesos[selP - 1].pid);
            g_exeTarget = procesos[selP - 1].nombre; // Almacenamos el nombre de cara al .cfg
            std::wcout << L"\n[OK] " << procesos[selP - 1].nombre << L" (PID " << procesos[selP - 1].pid << L") añadido.\n";
            Sleep(1000);
        }
    }

    // PASO 2: BUCLE DE BLOQUEO DE DISPOSITIVOS
    std::wstring input;
    while (true) {
        system("cls");
        std::wcout << L"=== PASO 2: GESTION DE DISPOSITIVOS (MandoShield) ===\n";
        std::wcout << L"Ejecuta el programa como administrador para que funcione.\n";
        if (!g_exeTarget.empty()) {
            std::wcout << L"Programa Whitelist configurado: " << g_exeTarget << L"\n";
            
            // Sincronización en caliente por si abres el juego después de iniciar MandoShield
            DWORD pidVivo = ObtenerPIDPorNombre(g_exeTarget);
            if (pidVivo != 0 && (g_whitelistPIDs.empty() || g_whitelistPIDs[0] != pidVivo)) {
                g_whitelistPIDs.clear();
                g_whitelistPIDs.push_back(pidVivo);
                AplicarCambios();
                ReiniciarHID();
            }
        }
        std::wcout << L"\n";
        
        auto mandos = ListarMandos();
        std::wcout << L"ID | ESTADO   | NOMBRE / HARDWARE ID\n";
        std::wcout << L"---|----------|------------------------------------\n";
        for (size_t i = 0; i < mandos.size(); i++) {
            bool b = std::find(g_bloqueados.begin(), g_bloqueados.end(), mandos[i].hwID) != g_bloqueados.end();
            std::wcout << i + 1 << L". [" << (b ? L"BLOQUEADO" : L" LIBRE   ") << L"] " << mandos[i].name << L"\n";
            std::wcout << L"   ID: " << mandos[i].hwID << L"\n\n";
        }

        std::wcout << L"OPCIONES:\n";
        std::wcout << L"- Ingrese numeros separados por coma (ejemplo: 1,2) para alternar bloqueo.\n";
        std::wcout << L"- [0] Salir, DESBLOQUEAR TODO y guardar cambios actuales en el .cfg\n";
        std::wcout << L"Seleccion: ";
        
        std::wcin >> input;

        if (input == L"0") {
            // Guardamos la configuración en disco justo antes de deshacer los cambios en el sistema
            GuardarConfiguracionArchivo();

            // Lógica exacta de salida efímera original: limpiar vectores, borrar registro y reiniciar driver
            g_bloqueados.clear();
            g_whitelistPIDs.clear();
            AplicarCambios();
            ReiniciarHID();
            std::wcout << L"Limpiando registros del sistema y saliendo de forma limpia...\n";
            break;
        }

        // Procesar múltiples selecciones (comas)
        std::wstringstream ss(input);
        std::wstring item;
        while (std::getline(ss, item, L',')) {
            try {
                int idx = std::stoi(item);
                if (idx > 0 && idx <= (int)mandos.size()) {
                    auto it = std::find(g_bloqueados.begin(), g_bloqueados.end(), mandos[idx - 1].hwID);
                    if (it != g_bloqueados.end()) {
                        g_bloqueados.erase(it);
                    } else {
                        g_bloqueados.push_back(mandos[idx - 1].hwID);
                    }
                }
            } catch (...) {}
        }

        if (!AplicarCambios()) {
            std::wcout << L"\n[!] ERROR: No se pudo escribir en el registro. ¿Eres Administrador?\n";
            Sleep(2000);
        }
        
        ReiniciarHID();
        std::wcout << L"\n[*] Procesando cambios...";
        Sleep(800);
    }

    return 0;
}
