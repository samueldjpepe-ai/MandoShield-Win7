#include <windows.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

// Función para configurar las llaves de registro de HidGuardian
void ConfigurarHidGuardian(std::wstring hardwareID) {
    HKEY hKey;
    // Ruta de configuración de HidGuardian Gen1
    std::wstring base = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        // 1. Whitelist: Se crea una subclave con el PID del proceso actual
        DWORD pid = GetCurrentProcessId();
        HKEY hWhitelist;
        std::wstring pidPath = L"Whitelist\\" + std::to_wstring(pid);
        if (RegCreateKeyExW(hKey, pidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hWhitelist, NULL) == ERROR_SUCCESS) {
            RegCloseKey(hWhitelist);
        }

        // 2. AffectedDevices: Se define el Hardware ID del mando a ocultar (formato REG_MULTI_SZ)
        // Se añade un doble nulo al final para cumplir con el formato de cadena múltiple
        std::wstring data = hardwareID + L"\0"; 
        RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)data.c_str(), (data.length() + 1) * sizeof(wchar_t));
        
        RegCloseKey(hKey);
        std::wcout << L"[OK] Mando configurado en HidGuardian: " << hardwareID << std::endl;
    } else {
        std::cout << " No se pudo abrir el registro. ¿Ejecuto como Administrador?" << std::endl;
    }
}

// Función para forzar que Windows reconozca los cambios sin reiniciar la PC
void ReiniciarDispositivosHID() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, L"HID", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (hDevInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        SP_PROPCHANGE_PARAMS pcp = { sizeof(SP_CLASSINSTALL_HEADER) };
        pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        pcp.StateChange = DICS_PROPCHANGE; // Forzar cambio de propiedad para reiniciar el nodo
        pcp.Scope = DICS_FLAG_CONFIGSPECIFIC;
        
        if (SetupDiSetClassInstallParamsW(hDevInfo, &devData, &pcp.ClassInstallHeader, sizeof(pcp))) {
            SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devData);
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    std::cout << "[INFO] Bus de dispositivos HID reiniciado." << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "   MandoShield v1.1 - Windows 7 Fix" << std::endl;
    std::cout << "========================================\n" << std::endl;

    // ID de Hardware de ejemplo (ID común de mandos genéricos)
    std::wstring mandoId = L"HID\\VID_0079&PID_0006"; 

    ConfigurarHidGuardian(mandoId);
    ReiniciarDispositivosHID();

    std::cout << "\nProceso terminado. Ya puede iniciar su juego." << std::endl;
    system("pause");
    return 0;
}
