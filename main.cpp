#include <windows.h>
#include <devguid.h>
#include <setupapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

struct MandoInfo {
    std::wstring name;
    std::wstring hwID;
};

std::vector<std::wstring> g_bloqueados;
std::vector<DWORD> g_whitelistPIDs;

// --- FUNCIONES DE PROCESOS ---

DWORD ObtenerPID(const std::wstring& nombre) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (nombre == pe.szExeFile) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

// --- GESTIÓN DE REGISTRO ---

void LimpiarWhitelist() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters\\Whitelist", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        for (DWORD pid : g_whitelistPIDs) {
            RegDeleteKeyW(hKey, std::to_wstring(pid).c_str());
        }
        RegCloseKey(hKey);
    }
    g_whitelistPIDs.clear();
}

bool AplicarCambios() {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) return false;

    // 1. Escribir AffectedDevices (Bloqueos)
    std::vector<wchar_t> multiSz;
    for (const auto& id : g_bloqueados) {
        for (wchar_t c : id) multiSz.push_back(c);
        multiSz.push_back(L'\0');
    }
    multiSz.push_back(L'\0');
    RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)multiSz.data(), (DWORD)(multiSz.size() * sizeof(wchar_t)));

    // 2. Asegurar nuestra propia Whitelist (para que el programa no se bloquee a sí mismo)
    std::wstring miPidPath = L"Whitelist\\" + std::to_wstring(GetCurrentProcessId());
    HKEY hSubKey;
    if (RegCreateKeyExW(hKey, miPidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hSubKey, NULL) == ERROR_SUCCESS) RegCloseKey(hSubKey);

    // 3. Escribir Whitelist de otros programas
    for (DWORD pid : g_whitelistPIDs) {
        std::wstring p = L"Whitelist\\" + std::to_wstring(pid);
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
            m.hwID = buf;
            if (m.hwID.find(L"VID_") != std::wstring::npos) lista.push_back(m);
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return lista;
}

// --- MAIN ---

int main() {
    _wsetlocale(LC_ALL, L"");
    std::wstring input;

    while (true) {
        system("cls");
        std::wcout << L"=== MandoShield V2 (Admin) ===\n\n";
        
        auto mandos = ListarMandos();
        std::wcout << L"--- DISPOSITIVOS ---\n";
        for (size_t i = 0; i < mandos.size(); i++) {
            bool b = std::find(g_bloqueados.begin(), g_bloqueados.end(), mandos[i].hwID) != g_bloqueados.end();
            std::wcout << i + 1 << L". [" << (b ? L"BLOQUEADO" : L"LIBRE") << L"] " << mandos[i].name << L"\n";
        }

        std::wcout << L"\n--- WHITELIST ACTUAL (PIDs) ---\n";
        if (g_whitelistPIDs.empty()) std::wcout << L"Ninguno\n";
        for (DWORD p : g_whitelistPIDs) std::wcout << L"PID: " << p << L" (Autorizado)\n";

        std::wcout << L"\nOPCIONES:\n";
        std::wcout << L"[numero] Alternar Bloqueo\n";
        std::wcout << L"[W] Añadir Programa a Whitelist (ej: dolphin.exe)\n";
        std::wcout << L"[C] Limpiar Whitelist\n";
        std::wcout << L"[0] Salir y Reset\n";
        std::wcout << L"Seleccion: ";
        
        std::wcin >> input;

        if (input == L"0") {
            g_bloqueados.clear();
            LimpiarWhitelist();
            AplicarCambios();
            ReiniciarHID();
            break;
        } else if (input == L"W" || input == L"w") {
            std::wcout << L"Nombre del .exe (exacto): ";
            std::wstring exe; std::wcin >> exe;
            DWORD pid = ObtenerPID(exe);
            if (pid != 0) {
                g_whitelistPIDs.push_back(pid);
                std::wcout << L"¡PID " << pid << L" añadido!\n";
            } else std::wcout << L"Programa no encontrado.\n";
            Sleep(1000);
        } else if (input == L"C" || input == L"c") {
            LimpiarWhitelist();
            std::wcout << L"Whitelist vaciada.\n";
            Sleep(1000);
        } else {
            try {
                int sel = std::stoi(input);
                if (sel > 0 && sel <= (int)mandos.size()) {
                    auto id = mandos[sel - 1].hwID;
                    auto it = std::find(g_bloqueados.begin(), g_bloqueados.end(), id);
                    if (it != g_bloqueados.end()) g_bloqueados.erase(it);
                    else g_bloqueados.push_back(id);
                }
            } catch (...) {}
        }

        if (!AplicarCambios()) std::wcout << L"¡ERROR DE PERMISOS! Ejecuta como ADMIN.\n";
        ReiniciarHID();
    }
    return 0;
}
