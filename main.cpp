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
    // Ordenar alfabéticamente para facilitar la lectura
    std::sort(lista.begin(), lista.end(), [](const ProcesoInfo& a, const ProcesoInfo& b) {
        return a.nombre < b.nombre;
    });
    return lista;
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

    // 2. Limpiar Whitelist antigua (opcional, para no acumular basura)
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

    // PASO 1: SELECCIÓN DE PROCESO PARA WHITELIST
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
        std::wcout << L"\n[OK] " << procesos[selP - 1].nombre << L" (PID " << procesos[selP - 1].pid << L") añadido.\n";
        Sleep(1000);
    }

    // PASO 2: BUCLE DE BLOQUEO DE DISPOSITIVOS
    std::wstring input;
    while (true) {
        system("cls");
        std::wcout << L"=== PASO 2: GESTION DE DISPOSITIVOS (MandoShield) ===\n";
        std::wcout << L"Ejecuta el programa como administrador para que funcione.\n\n";
        
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
        std::wcout << L"- [0] Salir y desbloquear todo.\n";
        std::wcout << L"Seleccion: ";
        
        std::wcin >> input;

        if (input == L"0") {
            g_bloqueados.clear();
            AplicarCambios();
            ReiniciarHID();
            std::wcout << L"Limpiando y saliendo...\n";
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
            } catch (...) {
                // Ignorar entradas que no sean números
            }
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
