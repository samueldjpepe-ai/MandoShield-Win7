#include <windows.h>
#include <devguid.h>
#include <setupapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>

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
std::wstring g_procesoWhitelisteadoNombre = L""; // Guarda el nombre del ejecutable para persistencia

// --- RUTA DEL REGISTRO PARA PASAR CONFIGURACIÓN ---
const LPCWSTR REG_PARAM_PATH = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
const LPCWSTR REG_MANDOSHIELD_PATH = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters\\MandoShieldPersist";

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

DWORD BuscarPIDPorNombre(const std::wstring& nombreExe) {
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

// --- PERSISTENCIA EN EL REGISTRO ---

void GuardarConfiguracion() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_MANDOSHIELD_PATH, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        // 1. Guardar el nombre del proceso autorizado
        RegSetValueExW(hKey, L"WhitelistExe", 0, REG_SZ, (BYTE*)g_procesoWhitelisteadoNombre.c_str(), (DWORD)((g_procesoWhitelisteadoNombre.length() + 1) * sizeof(wchar_t)));
        
        // 2. Guardar la lista de hardware IDs bloqueados (Multi-SZ)
        std::vector<wchar_t> multiSz;
        for (const auto& id : g_bloqueados) {
            for (wchar_t c : id) multiSz.push_back(c);
            multiSz.push_back(L'\0');
        }
        multiSz.push_back(L'\0');
        RegSetValueExW(hKey, L"Bloqueados", 0, REG_MULTI_SZ, (BYTE*)multiSz.data(), (DWORD)(multiSz.size() * sizeof(wchar_t)));
        
        RegCloseKey(hKey);
    }
}

void CargarConfiguracion() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_MANDOSHIELD_PATH, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // 1. Cargar nombre del proceso
        wchar_t exeBuffer[MAX_PATH] = { 0 };
        DWORD bufSize = sizeof(exeBuffer);
        if (RegQueryValueExW(hKey, L"WhitelistExe", NULL, NULL, (BYTE*)exeBuffer, &bufSize) == ERROR_SUCCESS) {
            g_procesoWhitelisteadoNombre = exeBuffer;
            if (!g_procesoWhitelisteadoNombre.empty()) {
                DWORD pid = BuscarPIDPorNombre(g_procesoWhitelisteadoNombre);
                if (pid != 0) {
                    g_whitelistPIDs.push_back(pid);
                }
            }
        }

        // 2. Cargar hardware IDs bloqueados
        DWORD multiSize = 0;
        if (RegQueryValueExW(hKey, L"Bloqueados", NULL, NULL, NULL, &multiSize) == ERROR_SUCCESS && multiSize > 2) {
            std::vector<wchar_t> multiSz(multiSize / sizeof(wchar_t));
            if (RegQueryValueExW(hKey, L"Bloqueados", NULL, NULL, (BYTE*)multiSz.data(), &multiSize) == ERROR_SUCCESS) {
                g_bloqueados.clear();
                wchar_t* p = multiSz.data();
                while (*p) {
                    std::wstring id(p);
                    if (!id.empty()) g_bloqueados.push_back(id);
                    p += id.length() + 1;
                }
            }
        }
        RegCloseKey(hKey);
    }
}

// --- GESTIÓN DE HIDGUARDIAN ---

bool AplicarCambios() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PARAM_PATH, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) return false;

    // 1. AffectedDevices (Multi-SZ)
    std::vector<wchar_t> multiSz;
    for (const auto& id : g_bloqueados) {
        for (wchar_t c : id) multiSz.push_back(c);
        multiSz.push_back(L'\0');
    }
    multiSz.push_back(L'\0'); 
    RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)multiSz.data(), (DWORD)(multiSz.size() * sizeof(wchar_t)));

    // 2. Limpiar e inyectar Whitelist de PIDs dinámicos
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
    
    // Guardar el estado actual en nuestro almacén persistente
    GuardarConfiguracion();
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

    // CARGAR CONFIGURACIÓN PREVIA AL INICIAR
    CargarConfiguracion();

    // PASO 1: SELECCIÓN DE PROCESO PARA WHITELIST
    auto procesos = ListarProcesosUsuario();
    std::wcout << L"=== PASO 1: SELECCIONAR PROGRAMA PARA WHITELIST ===\n";
    
    if (!g_procesoWhitelisteadoNombre.empty()) {
        std::wcout << L"[PERSISTENCIA] Programa guardado anteriormente: " << g_procesoWhitelisteadoNombre << L"\n";
        if (!g_whitelistPIDs.empty()) {
            std::wcout << L"[*] Encontrado ejecutándose con PID: " << g_whitelistPIDs[0] << L" (Auto-autorizado).\n\n";
        } else {
            std::wcout << L"[!] El programa guardado NO está abierto actualmente.\n\n";
        }
    }

    std::wcout << L"Lista de procesos activos (Usuario):\n";
    for (size_t i = 0; i < procesos.size(); i++) {
        std::wcout << (i + 1) << L". " << procesos[i].nombre << L"\t";
        if ((i + 1) % 3 == 0) std::wcout << L"\n";
    }
    
    std::wcout << L"\n\nIngrese el NUMERO para cambiar/autorizar proceso (0 para mantener actual u omitir): ";
    int selP;
    if (!(std::wcin >> selP)) {
        std::wcin.clear();
        std::wcin.ignore(10000, L'\n');
        selP = 0;
    }

    if (selP > 0 && selP <= (int)procesos.size()) {
        g_whitelistPIDs.clear(); // Limpiar el anterior PID
        g_whitelistPIDs.push_back(procesos[selP - 1].pid);
        g_procesoWhitelisteadoNombre = procesos[selP - 1].nombre; // Guardar texto ejecutable
        std::wcout << L"\n[OK] " << g_procesoWhitelisteadoNombre << L" asignado a la persistencia.\n";
        Sleep(1000);
    }

    // Aplicar la configuración inicial recuperada de inmediato
    AplicarCambios();
    ReiniciarHID();

    // PASO 2: BUCLE DE BLOQUEO DE DISPOSITIVOS
    std::wstring input;
    while (true) {
        system("cls");
        std::wcout << L"=== PASO 2: GESTION DE DISPOSITIVOS (MandoShield) ===\n";
        std::wcout << L"Ejecuta el programa como administrador para que funcione.\n";
        if (!g_procesoWhitelisteadoNombre.empty()) {
            std::wcout << L"Whitelist actual activa para: " << g_procesoWhitelisteadoNombre << L"\n";
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
        std::wcout << L"- [0] Salir manteniendo el bloqueo actual para otro dia.\n";
        std::wcout << L"- [limpiar] Desbloquear todo, borrar registro y salir.\n";
        std::wcout << L"Seleccion: ";
        
        std::wcin >> input;

        if (input == L"0") {
            std::wcout << L"Configuracion guardada correctamente. Saliendo...\n";
            break; 
        }

        if (input == L"limpiar") {
            g_bloqueados.clear();
            g_procesoWhitelisteadoNombre = L"";
            g_whitelistPIDs.clear();
            
            // Borrar nuestra subclave de persistencia
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, REG_MANDOSHIELD_PATH);
            
            AplicarCambios();
            ReiniciarHID();
            std::wcout << L"Todo limpio. Saliendo...\n";
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
        std::wcout << L"\n[*] Procesando y guardando cambios...";
        Sleep(800);
    }

    return 0;
}
