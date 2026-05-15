#include <windows.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

void ConfigurarHidGuardian(std::wstring hardwareID) {
    HKEY hKey;
    // La ruta base de HidGuardian Gen1 [1]
    std::wstring base = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        // 1. Whitelist: Crear subclave con el PID actual [5]
        DWORD pid = GetCurrentProcessId();
        HKEY hWhitelist;
        std::wstring pidPath = L"Whitelist\\" + std::to_wstring(pid);
        RegCreateKeyExW(hKey, pidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hWhitelist, NULL);
        RegCloseKey(hWhitelist);

        // 2. AffectedDevices: Escribir el ID del mando como REG_MULTI_SZ [5, 6]
        std::wstring data = hardwareID + L"\0"; 
        RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)data.c_str(), (data.length() + 1) * sizeof(wchar_t));
        
        RegCloseKey(hKey);
        std::wcout << L"Configurado para bloquear: " << hardwareID << std::endl;
    }
}

void ReiniciarDispositivos() {
    // Forzar re-enumeración mediante SetupAPI [3, 7, 4]
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, L"HID", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        SP_PROPCHANGE_PARAMS pcp = { sizeof(SP_CLASSINSTALL_HEADER) };
        pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        pcp.StateChange = DICS_PROPCHANGE; // Valor para resetear el dispositivo [4]
        pcp.Scope = DICS_FLAG_CONFIGSPECIFIC;
        
        if (SetupDiSetClassInstallParamsW(hDevInfo, &devData, &pcp.ClassInstallHeader, sizeof(pcp))) {
            SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devData);
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
}

int main() {
    std::cout << "MandoShield v1.0 - Win7\n";
    // Hardware ID de ejemplo (puedes pedirlo por consola)
    std::wstring mandoId = L"HID\\VID_0079&PID_0006"; 

    ConfigurarHidGuardian(mandoId);
    ReiniciarDispositivos();

    std::cout << "Proceso completado. Ejecute como Administrador para exito.\n";
    system("pause");
    return 0;
}
