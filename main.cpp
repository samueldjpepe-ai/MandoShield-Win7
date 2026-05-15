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
                // Filtro simple para evitar procesos de sistema básicos (opcional)
                if (pe.th32ProcessID > 400) { 
                    lista.push_back({ pe.th32ProcessID, pe.szExeFile });
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return lista;
}

// --- GESTIÓN DE REGISTRO ---

bool AplicarCambios() {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) return false;

    // 1. AffectedDevices
    std::vector<wchar_t> multiSz;
    for (const auto& id : g_bloqueados) {
        for (wchar_t c : id) multiSz.push_back(c);
        multiSz.push_back(L'\0');
    }
    multiSz.push_back(L'\0');
    RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)multiSz.data(), (DWORD)(multiSz.size() * sizeof(wchar_t)));

    // 2. Whitelist (incluyendo el PID propio)
    g_whitelistPIDs.push_back(GetCurrentProcessId());
    for (DWORD pid : g_whitelistPIDs) {
        std::wstring p = L"Whitelist\\" + std::to_wstring(pid);
        HKEY hSubKey;
        if (RegCreateKeyExW(hKey, p.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hSubKey, NULL) == ERROR_SUCCESS) RegCloseKey(hSubKey);
    }
    RegCloseKey(hKey);
    return true;
}

void ReiniciarHID() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_HIDCLASS, NULL, NULL, DIGCF_PRESENT);
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
    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        wchar_t buf[512];
        MandoInfo m;
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)buf, sizeof(buf), NULL) ||
            SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_DEVICEDESC, NULL, (PBYTE)buf, sizeof(buf), NULL)) m.name = buf;
        
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_HARDWAREID, NULL, (PBYTE)buf, sizeof(buf), NULL)) {
            m.hwID = buf; // El primer ID de la lista suele ser el más específico
            if (m.hwID.find(L"VID_") != std::wstring::npos) lista.push_back(m);
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return lista;
}

int main() {
    _wsetlocale(LC_ALL, L"");

    // PASO 1: SELECCIÓN DE PROCESO PARA WHITELIST
    auto procesos = ListarProcesosUsuario();
    std::wcout << L"=== PASO 1: SELECCIONAR PROGRAMA (WHITELIST) ===\n";
    for (size_t i = 0; i < procesos.size(); i++) {
        if (i % 3 == 0) std::wcout << L"\n"; // Organizar en columnas simples
        std::wcout << i + 1 << L". " << procesos[i].nombre << L"  ";
        if (i > 60) break; // Limitar para no saturar la pantalla
    }
    
    std::wcout << L"\n\nIngrese el numero del programa a autorizar (0 para ninguno): ";
    int selP; std::cin >> selP;
    if (selP > 0 && selP <= (int)procesos.size()) {
        g_whitelistPIDs.push_back(procesos[selP - 1].pid);
        std::wcout << L"[OK] " << procesos[selP - 1].nombre << L" añadido a lista blanca.\n";
    }

    // PASO 2: BUCLE DE BLOQUEO DE DISPOSITIVOS
    std::wstring input;
    while (true) {
        system("cls");
        std::wcout << L"=== PASO 2: GESTION DE DISPOSITIVOS (MandoShield) ===\n\n";
        
        auto mandos = ListarMandos();
        std::wcout << L"ID | ESTADO | DISPOSITIVO / HARDWARE ID\n";
        std::wcout << L"--------------------------------------------------\n";
        for (size_t i = 0; i < mandos.size(); i++) {
            bool b = std::find(g_bloqueados.begin(), g_bloqueados.end(), mandos[i].hwID) != g_bloqueados.end();
            std::wcout << i + 1 << L". [" << (b ? L"BLOQUEADO" : L"LIBRE") << L"] " << mandos[i].name << L"\n";
            std::wcout << L"   ID EXACTO: " << mandos[i].hwID << L"\n\n";
        }

        std::wcout << L"OPCIONES:\n";
        std::wcout << L"- Ingrese números separados por coma para bloquear/liberar (ej: 1,2)\n";
        std::wcout << L"- [0] Salir y restaurar todo\n";
        std::wcout << L"Seleccion: ";
        
        std::cin >> input;
        if (input == L"0") {
            g_bloqueados.clear();
            AplicarCambios();
            ReiniciarHID();
            break;
        }

        // Procesar entrada con comas
        std::wstringstream ss(input);
        std::wstring item;
        while (std::getline(ss, item, L',')) {
            try {
                int idx = std::stoi(item);
                if (idx > 0 && idx <= (int)mandos.size()) {
                    auto it = std::find(g_bloqueados.begin(), g_bloqueados.end(), mandos[idx - 1].hwID);
                    if (it != g_bloqueados.end()) g_bloqueados.erase(it);
                    else g_bloqueados.push_back(mandos[idx - 1].hwID);
                }
            } catch (...) {}
        }

        if (!AplicarCambios()) std::wcout << L"\n[!] ERROR: Ejecuta como Administrador.\n";
        ReiniciarHID();
        std::wcout << L"\n[*] Cambios aplicados. Recargando...";
        Sleep(1000);
    }

    return 0;
}
