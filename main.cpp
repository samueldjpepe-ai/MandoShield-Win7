#include <windows.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

// 1. Verifica si el driver esta activado como "Muro" [1, 2]
bool IsFilterActive() {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}";
    wchar_t buffer;
    DWORD size = sizeof(buffer);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"UpperFilters", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            std::wstring filters(buffer);
            RegCloseKey(hKey);
            return (filters.find(L"HidGuardian")!= std::wstring::npos);
        }
        RegCloseKey(hKey);
    }
    return false;
}

// 2. Configura el bloqueo real en el registro 
void ForceBlock(std::wstring hardwareID) {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        // Formato REG_MULTI_SZ con doble nulo al final 
        std::vector<wchar_t> data(hardwareID.begin(), hardwareID.end());
        data.push_back(L'\0');
        data.push_back(L'\0');
        RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)data.data(), (DWORD)(data.size() * sizeof(wchar_t)));

        // Crea la subclave de Whitelist con nuestro PID 
        std::wstring pidKey = L"Whitelist\\" + std::to_wstring(GetCurrentProcessId());
        HKEY hWhite;
        RegCreateKeyExW(hKey, pidKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hWhite, NULL);
        RegCloseKey(hWhite);
        RegCloseKey(hKey);
    }
}

// 3. Reinicia el hardware para que el driver lo atrape 
void RestartDevices() {
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
    if (!IsFilterActive()) {
        std::cout << "[!] ERROR: HidGuardian no esta activo. Corra el comando devcon primero.\n";
        system("pause"); return 1;
    }

    // CAMBIE ESTE ID por el que sale en su Administrador de Dispositivos
    std::wstring miMando = L"HID\\VID_0079&PID_0006";

    ForceBlock(miMando);
    RestartDevices();

    std::cout << "[OK] Bloqueado. NO CIERRE esta ventana mientras juega.\n";
    while(true) Sleep(1000); // Mantiene el PID en la lista blanca 
    return 0;
}
