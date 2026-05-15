#include <windows.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <signal.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

// Variables globales para limpieza
std::wstring g_pidPath = L"";

// 1. Verifica si el driver HidGuardian está configurado como filtro de clase
bool IsFilterActive() {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD size = 0;
        if (RegQueryValueExW(hKey, L"UpperFilters", NULL, NULL, NULL, &size) == ERROR_SUCCESS) {
            std::vector<wchar_t> buffer(size / sizeof(wchar_t));
            if (RegQueryValueExW(hKey, L"UpperFilters", NULL, NULL, (LPBYTE)buffer.data(), &size) == ERROR_SUCCESS) {
                std::wstring filters(buffer.data(), size / sizeof(wchar_t));
                RegCloseKey(hKey);
                return (filters.find(L"HidGuardian") != std::wstring::npos);
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

// 2. Agrega el ID del mando a la lista de bloqueados y el proceso actual a la lista blanca
bool ForceBlock(std::wstring hardwareID) {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    // Escribir AffectedDevices (REG_MULTI_SZ requiere doble nulo al final)
    std::vector<wchar_t> data(hardwareID.begin(), hardwareID.end());
    data.push_back(L'\0'); 
    data.push_back(L'\0'); 

    if (RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, 
                       (BYTE*)data.data(), (DWORD)(data.size() * sizeof(wchar_t))) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    // Whitelist basada en nuestro PID
    g_pidPath = L"Whitelist\\" + std::to_wstring(GetCurrentProcessId());
    HKEY hWhite;
    if (RegCreateKeyExW(hKey, g_pidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hWhite, NULL) == ERROR_SUCCESS) {
        RegCloseKey(hWhite);
    }

    RegCloseKey(hKey);
    return true;
}

// 3. Reinicia los dispositivos HID para que el driver intercepte el mando
void RestartHID() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, L"HID", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
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

// Función de limpieza al salir
void Cleanup(int signum) {
    if (!g_pidPath.empty()) {
        HKEY hKey;
        LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            RegDeleteKeyW(hKey, g_pidPath.c_str());
            RegCloseKey(hKey);
            std::cout << "\n[INFO] Limpieza de Whitelist completada.\n";
        }
    }
    exit(signum);
}

int main() {
    // Configurar señales de salida para limpiar el registro
    signal(SIGINT, Cleanup);
    signal(SIGTERM, Cleanup);

    std::cout << "====================================\n";
    std::cout << "      MandoShield - HidGuardian     \n";
    std::cout << "====================================\n\n";

    if (!IsFilterActive()) {
        std::cout << "[!] ERROR: HidGuardian NO esta configurado como Filtro de Clase.\n";
        std::cout << "Ejecuta esto en PowerShell como Admin primero:\n";
        std::cout << "devcon classfilter HIDClass upper -HidGuardian\n\n";
        system("pause");
        return 1;
    }

    // ID de hardware del mando (Cambia esto por el tuyo si es necesario)
    std::wstring miMando = L"HID\\VID_0079&PID_0006";

    std::cout << "[*] Intentando bloquear mando: " << std::string(miMando.begin(), miMando.end()) << "...\n";

    if (ForceBlock(miMando)) {
        std::cout << "[*] Reiniciando pila HID (la pantalla/mouse pueden parpadear)...\n";
        RestartHID();
        std::cout << "[OK] Mando ocultado exitosamente.\n";
        std::cout << "[!] NO CIERRES esta ventana. Presiona Ctrl+C para salir y desbloquear.\n";
        
        while (true) Sleep(1000);
    } else {
        std::cout << "[!] ERROR: No se pudo escribir en el registro. ¿Ejecutaste como Administrador?\n";
    }

    system("pause");
    return 0;
}
