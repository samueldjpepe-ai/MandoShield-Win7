#include <windows.h>
#include <devguid.h> // Soluciona el error C2065
#include <setupapi.h>
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

// Lista global de IDs bloqueados actualmente
std::vector<std::wstring> g_bloqueados;

// --- FUNCIONES DE APOYO ---

// 1. Detectar mandos conectados
std::vector<MandoInfo> ListarMandos() {
    std::vector<MandoInfo> lista;
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_HIDCLASS, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return lista;

    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        wchar_t buffer[512];
        MandoInfo mando;

        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)buffer, sizeof(buffer), NULL) ||
            SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_DEVICEDESC, NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
            mando.name = buffer;
        } else {
            mando.name = L"Dispositivo desconocido";
        }

        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_HARDWAREID, NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
            mando.hwID = buffer;
            if (mando.hwID.find(L"VID_") != std::wstring::npos) {
                lista.push_back(mando);
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return lista;
}

// 2. Actualizar el registro con la lista actual de g_bloqueados
bool ActualizarRegistroHidGuardian() {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) return false;

    // Crear el bloque REG_MULTI_SZ (todas las IDs separadas por nulo y doble nulo al final)
    std::vector<wchar_t> multiSzData;
    for (const auto& id : g_bloqueados) {
        for (wchar_t c : id) multiSzData.push_back(c);
        multiSzData.push_back(L'\0'); 
    }
    multiSzData.push_back(L'\0'); // Doble terminación

    RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)multiSzData.data(), (DWORD)(multiSzData.size() * sizeof(wchar_t)));

    // Asegurar que el proceso actual está en la Whitelist para no bloquearse a sí mismo
    std::wstring pidPath = L"Whitelist\\" + std::to_wstring(GetCurrentProcessId());
    HKEY hWhite;
    if (RegCreateKeyExW(hKey, pidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hWhite, NULL) == ERROR_SUCCESS) {
        RegCloseKey(hWhite);
    }

    RegCloseKey(hKey);
    return true;
}

// 3. Reiniciar el stack HID para aplicar cambios
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

// --- MAIN ---

int main() {
    _wsetlocale(LC_ALL, L"");

    while (true) {
        system("cls");
        std::cout << "======================================\n";
        std::cout << "      MandoShield: Multi-Control      \n";
        std::cout << "======================================\n\n";

        std::vector<MandoInfo> mandos = ListarMandos();
        
        std::cout << "--- DISPOSITIVOS DETECTADOS ---\n";
        for (size_t i = 0; i < mandos.size(); i++) {
            bool estaBloqueado = std::find(g_bloqueados.begin(), g_bloqueados.end(), mandos[i].hwID) != g_bloqueados.end();
            
            std::wcout << i + 1 << L". [" << (estaBloqueado ? L"BLOQUEADO" : L"LIBRE") << L"] " 
                       << mandos[i].name << L"\n    ID: " << mandos[i].hwID << L"\n\n";
        }

        std::cout << "--------------------------------------\n";
        std::cout << "Opciones:\n";
        std::cout << "[Numero] Bloquear/Desbloquear dispositivo\n";
        std::cout << "[0] Salir y liberar TODO\n";
        std::cout << "Seleccion: ";

        int seleccion;
        if (!(std::cin >> seleccion)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }

        if (seleccion == 0) {
            g_bloqueados.clear();
            ActualizarRegistroHidGuardian();
            ReiniciarHID();
            break;
        }

        if (seleccion > 0 && seleccion <= (int)mandos.size()) {
            std::wstring idSeleccionado = mandos[seleccion - 1].hwID;
            auto it = std::find(g_bloqueados.begin(), g_bloqueados.end(), idSeleccionado);

            if (it != g_bloqueados.end()) {
                // Si ya estaba, lo liberamos
                g_bloqueados.erase(it);
                std::cout << "[*] Liberando dispositivo...\n";
            } else {
                // Si no estaba, lo bloqueamos
                g_bloqueados.push_back(idSeleccionado);
                std::cout << "[*] Bloqueando dispositivo...\n";
            }

            if (ActualizarRegistroHidGuardian()) {
                ReiniciarHID();
                std::cout << "[OK] Cambios aplicados.\n";
            } else {
                std::cout << "[!] ERROR: No se pudo acceder al registro (ejecuta como Admin).\n";
            }
            Sleep(1500);
        }
    }

    return 0;
}
