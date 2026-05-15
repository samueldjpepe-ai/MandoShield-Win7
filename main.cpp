#include <windows.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

// 1. FUNCION DE DIAGNOSIS (El "Muro")
bool CheckFilterActive() {
    HKEY hKey;
    LPCWSTR classPath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}";
    wchar_t filters;
    DWORD size = sizeof(filters);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, classPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"UpperFilters", NULL, NULL, (LPBYTE)filters, &size) == ERROR_SUCCESS) {
            std::wstring f(filters);
            if (f.find(L"HidGuardian")!= std::wstring::npos) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

// 2. CONFIGURACION REAL [1, 2]
void ForceBlock(std::wstring hardwareID) {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        // Bloqueo de mandos (Doble null al final para MULTI_SZ)
        std::wstring data = hardwareID + L"\0\0";
        RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)data.c_str(), (data.length() + 1) * sizeof(wchar_t));
        
        // Whitelist para este programa (PID)
        HKEY hWhite;
        std::wstring pidKey = L"Whitelist\\" + std::to_wstring(GetCurrentProcessId());
        RegCreateKeyExW(hKey, pidKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hWhite, NULL);
        RegCloseKey(hWhite);
        
        RegCloseKey(hKey);
    }
}

// 3. REINICIO DE HARDWARE
void RestartHID() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, L"HID", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        SP_PROPCHANGE_PARAMS pcp = { sizeof(SP_CLASSINSTALL_HEADER) };
        pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        pcp.StateChange = DICS_PROPCHANGE;
        pcp.Scope = DICS_FLAG_GLOBAL;
        if (SetupDiSetClassInstallParamsW(hDevInfo, &devData, &pcp.ClassInstallHeader, sizeof(pcp))) {
            SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devData);
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
}

int main() {
    std::cout << "--- DIAGNOSIS DE HIDGUARDIAN ---" << std::endl;
    
    if (!CheckFilterActive()) {
        std::cout << "[!] ERROR CRITICO: HidGuardian NO esta activo como Filtro de Clase." << std::endl;
        std::cout << "Ejecute esto en PowerShell como Admin: \n" ;
        std::cout << "devcon classfilter HIDClass upper -HidGuardian" << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[+] Filtro detectado. Bloqueando mandos..." << std::endl;
    
    // Use el ID que sale en su Administrador de Dispositivos (IDs de hardware)
    ForceBlock(L"HID\\VID_0079&PID_0006"); 
    RestartHID();

    std::cout << "[OK] Mandos bloqueados. NO CIERRE esta ventana mientras juega." << std::endl;
    std::cout << "Si la cierra, el juego vera el mando otra vez." << std::endl;

    while(true) Sleep(1000); // Mantiene el PID en la Whitelist
    return 0;
}
