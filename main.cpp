#include <windows.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <signal.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

struct MandoInfo {
    std::wstring name;
    std::wstring hwID;
};

std::wstring g_pidPath = L"";

// --- FUNCIONES DE APOYO ---

// Limpieza de la lista blanca al salir
void Cleanup(int signum) {
    if (!g_pidPath.empty()) {
        HKEY hKey;
        LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            RegDeleteKeyW(hKey, g_pidPath.c_str());
            RegCloseKey(hKey);
            std::cout << "\n[INFO] Whitelist limpiada. Saliendo...\n";
        }
    }
    exit(signum);
}

// 1. Detectar mandos conectados
std::vector<MandoInfo> ListarMandos() {
    std::vector<MandoInfo> lista;
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_HIDCLASS, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return lista;

    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        wchar_t buffer[512];
        MandoInfo mando;

        // Intentar obtener el nombre amigable o la descripción
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)buffer, sizeof(buffer), NULL) ||
            SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_DEVICEDESC, NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
            mando.name = buffer;
        } else {
            mando.name = L"Dispositivo desconocido";
        }

        // Obtener el Hardware ID (usamos el primero de la lista que devuelve el sistema)
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_HARDWAREID, NULL, (PBYTE)buffer, sizeof(buffer), NULL)) {
            mando.hwID = buffer;
            // Filtrar: solo añadir si parece un mando (VID/PID) y no es un componente virtual
            if (mando.hwID.find(L"VID_") != std::wstring::npos) {
                lista.push_back(mando);
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return lista;
}

// 2. Bloquear mando seleccionado
bool BloquearMando(std::wstring hardwareID) {
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) return false;

    // REG_MULTI_SZ: ID + doble nulo
    std::vector<wchar_t> data(hardwareID.begin(), hardwareID.end());
    data.push_back(L'\0'); 
    data.push_back(L'\0'); 

    RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)data.data(), (DWORD)(data.size() * sizeof(wchar_t)));

    // Whitelist PID
    g_pidPath = L"Whitelist\\" + std::to_wstring(GetCurrentProcessId());
    HKEY hWhite;
    RegCreateKeyExW(hKey, g_pidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hWhite, NULL);
    RegCloseKey(hWhite);

    RegCloseKey(hKey);
    return true;
}

// 3. Reiniciar HID
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
    signal(SIGINT, Cleanup);
    _wsetlocale(LC_ALL, L""); // Soporte para caracteres especiales

    std::cout << "======================================\n";
    std::cout << "      MandoShield: Selector HID       \n";
    std::cout << "======================================\n\n";

    std::cout << "[*] Escaneando mandos conectados...\n";
    std::vector<MandoInfo> mandos = ListarMandos();

    if (mandos.empty()) {
        std::cout << "[!] No se detectaron mandos HID.\n";
        system("pause");
        return 0;
    }

    for (size_t i = 0; i < mandos.size(); i++) {
        std::wcout << i + 1 << L". " << mandos[i].name << L"\n";
        std::wcout << L"   ID: " << mandos[i].hwID << L"\n\n";
    }

    int seleccion;
    std::cout << "Seleccione el numero de mando a BLOQUEAR (0 para cancelar): ";
    std::cin >> seleccion;

    if (seleccion > 0 && seleccion <= (int)mandos.size()) {
        std::wstring idSeleccionado = mandos[seleccion - 1].hwID;
        
        std::cout << "[*] Aplicando bloqueo...\n";
        if (BloquearMando(idSeleccionado)) {
            ReiniciarHID();
            std::cout << "\n[OK] Mando bloqueado exitosamente.\n";
            std::cout << "[!] No cierres esta ventana para mantener el acceso.\n";
            std::cout << "[!] Presiona Ctrl+C para salir y liberar el mando.\n";
            while (true) Sleep(1000);
        } else {
            std::cout << "[!] ERROR: Revisa si eres Administrador.\n";
        }
    } else {
        std::cout << "Operacion cancelada.\n";
    }

    system("pause");
    return 0;
}
