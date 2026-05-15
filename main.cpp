#include <windows.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

// 1. Verifica si HidGuardian es el "Muro" activo [1, 2]
bool IsFilterActive() {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD size = 0;
        if (RegQueryValueExW(hKey, L"UpperFilters", NULL, NULL, NULL, &size) == ERROR_SUCCESS) {
            std::vector<wchar_t> buffer(size / sizeof(wchar_t));
            if (RegQueryValueExW(hKey, L"UpperFilters", NULL, NULL, (LPBYTE)buffer.data(), &size) == ERROR_SUCCESS) {
                std::wstring filters(buffer.data());
                RegCloseKey(hKey);
                return (filters.find(L"HidGuardian")!= std::wstring::npos);
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

// 2. Bloquea el mando y se pone en lista blanca [3, 4]
void ForceBlock(std::wstring hardwareID) {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        // Formato MULTI_SZ (Doble nulo al final) [3, 5]
        std::vector<wchar_t> data(hardwareID.begin(), hardwareID.end());
        data.push_back(L'\0'); data.push_back(L'\0');
        RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)data.data(), (DWORD)(data.size() * sizeof(wchar_t)));

        // Whitelist basada en nuestro PID 
        std::wstring pidKey = L"Whitelist\\" + std::to_wstring(GetCurrentProcessId());
        HKEY hWhite;
        RegCreateKeyExW(hKey, pidKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hWhite, NULL);
        RegCloseKey(hWhite);
        RegCloseKey(hKey);
    }
}

// 3. Reinicia la pila HID para aplicar cambios 
void RestartHID() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, L"HID", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        SP_PROPCHANGE_PARAMS pcp = { {sizeof(SP_CLASSINSTALL_HEADER), DIF_PROPERTYCHANGE}, DICS_PROPCHANGE, DICS_FLAG_GLOBAL, 0 };
        if (SetupDiSetClassInstallParamsW(hDevInfo, &devData, &pcp.ClassInstallHeader, sizeof(pcp))) {
            SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devData);
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
}

int main() {
    std::cout << "--- MandoShield Win7 ---\n";
    if (!IsFilterActive()) {
        std::cout << "[!] ERROR: HidGuardian NO esta activado como Filtro de Clase.\n";
        std::cout << "Paso obligatorio: Ejecute en PowerShell como Admin:\n";
        std::cout << "devcon classfilter HIDClass upper -HidGuardian\n";
        system("pause"); return 1;
    }

    // Hardware ID del mando fisico a ocultar 
    std::wstring miMando = L"HID\\VID_0079&PID_0006";

    ForceBlock(miMando);
    RestartHID();

    std::cout << "[OK] Mando bloqueado. NO CIERRE esta ventana para mantener el permiso.\n";
    while(true) Sleep(1000); // Mantiene el proceso vivo 
    return 0;
}
