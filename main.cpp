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
std::wstring g_exeTarget = L""; // Guarda el nombre del ejecutable persistente (ej: pcsx2.exe)

const LPCWSTR PATH_HIDGUARDIAN = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters";
const LPCWSTR PATH_MANDOSHIELD  = L"SYSTEM\\CurrentControlSet\\Services\\HidGuardian\\Parameters\\MandoShield";

// --- FUNCIONES DE PROCESOS ---

std::vector<ProcesoInfo> ListarProcesosUsuario() {
    std::vector<ProcesoInfo> lista;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID > 400) { 
                    lista.push_back({ pe.th32ProcessID, pe.szExeFile });
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    std::sort(lista.begin(), lista.end(), [](const ProcesoInfo& a, const ProcesoInfo& b) {
        return a.nombre < b.nombre;
    });
    return lista;
}

DWORD ObtenerPIDPorNombre(const std::wstring& nombreExe) {
    if (nombreExe.empty()) return 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, nombreExe.c_str()) == 0) {
                    CloseHandle(hSnap);
                    return pe.th32ProcessID;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return 0;
}

// --- PERSISTENCIA LOCAL EN REGISTRO ---

void GuardarConfiguracionLocal() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, PATH_MANDOSHIELD, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        // Guardar nombre del EXE
        RegSetValueExW(hKey, L"TargetExe", 0, REG_SZ, (BYTE*)g_exeTarget.c_str(), (DWORD)((g_exeTarget.length() + 1) * sizeof(wchar_t)));
        
        // Guardar Mandos Bloqueados (Multi-SZ)
        std::vector<wchar_t> multiSz;
        for (const auto& id : g_bloqueados) {
            for (wchar_t c : id) multiSz.push_back(c);
            multiSz.push_back(L'\0');
        }
        multiSz.push_back(L'\0');
        RegSetValueExW(hKey, L"Bloqueados", 0, REG_MULTI_SZ, (BYTE*)multiSz.data(), (DWORD)(multiSz.size() * sizeof(wchar_t)));
        
        RegCloseKey(hKey);
    }
}

void CargarConfiguracionLocal() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PATH_MANDOSHIELD, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t bufExe[MAX_PATH] = {0};
        DWORD sizeExe = sizeof(bufExe);
        if (RegQueryValueExW(hKey, L"TargetExe", NULL, NULL, (BYTE*)bufExe, &sizeExe) == ERROR_SUCCESS) {
            g_exeTarget = bufExe;
        }

        DWORD sizeBloq = 0;
        if (RegQueryValueExW(hKey, L"Bloqueados", NULL, NULL, NULL, &sizeBloq) == ERROR_SUCCESS && sizeBloq > 2) {
            std::vector<wchar_t> multiSz(sizeBloq / sizeof(wchar_t));
            if (RegQueryValueExW(hKey, L"Bloqueados", NULL, NULL, (BYTE*)multiSz.data(), &sizeBloq) == ERROR_SUCCESS) {
                g_bloqueados.clear();
                wchar_t* p = multiSz.data();
                while (*p) {
                    std::wstring id(p);
                    if (!id.empty()) g_bloqueados.push_back(id);
                    p += id.length() + 1;
                }
            }
        }
        RegCloseKey(hKey);
    }
}

// Limpia las subclaves dinámicas de Whitelist previas para evitar desorden
void LimpiarWhitelistRegistro(HKEY hKeyPadre) {
    HKEY hKeyWhitelist;
    if (RegOpenKeyExW(hKeyPadre, L"Whitelist", 0, KEY_ALL_ACCESS, &hKeyWhitelist) == ERROR_SUCCESS) {
        wchar_t subKeyName[256];
        DWORD nameSize = 256;
        while (RegEnumKeyExW(hKeyWhitelist, 0, subKeyName, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            RegDeleteKeyW(hKeyWhitelist, subKeyName);
            nameSize = 256;
        }
        RegCloseKey(hKeyWhitelist);
    }
}

// --- GESTIÓN DE REGISTRO HIDGUARDIAN ---

bool AplicarCambios() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PATH_HIDGUARDIAN, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) return false;

    // 1. Escribir AffectedDevices (Mandos bloqueados)
    std::vector<wchar_t> multiSz;
    for (const auto& id : g_bloqueados) {
        for (wchar_t c : id) multiSz.push_back(c);
        multiSz.push_back(L'\0');
    }
    multiSz.push_back(L'\0');
    RegSetValueExW(hKey, L"AffectedDevices", 0, REG_MULTI_SZ, (BYTE*)multiSz.data(), (DWORD)(multiSz.size() * sizeof(wchar_t)));

    // 2. Limpiar e inyectar la Whitelist basada en PIDs frescos
    LimpiarWhitelistRegistro(hKey);

    std::vector<DWORD> pidsTemp = g_whitelistPIDs;
    pidsTemp.push_back(GetCurrentProcessId()); // Incluir siempre este configurador

    for (DWORD pid : pidsTemp) {
        std::wstring p = L"Whitelist\\" + std::to_wstring(pid);
        HKEY hSubKey;
        if (RegCreateKeyExW(hKey, p.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hSubKey, NULL) == ERROR_SUCCESS) {
            RegCloseKey(hSubKey);
        }
    }
    RegCloseKey(hKey);
    
    // Guardar nuestro estado actual en el almacén persistente
    GuardarConfiguracionLocal();
    return true;
}

void ReiniciarHID() {
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_HIDCLASS, NULL, NULL, DIGCF_PRESENT);
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

std::vector<MandoInfo> ListarMandos() {
    std::vector<MandoInfo> lista;
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_HIDCLASS, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return lista;

    SP_DEVINFO_DATA devData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
        wchar_t buf[1024];
        MandoInfo m;
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)buf, sizeof(buf), NULL) ||
            SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_DEVICEDESC, NULL, (PBYTE)buf, sizeof(buf), NULL)) {
            m.name = buf;
        } else {
            m.name = L"Dispositivo desconocido";
        }
        
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_HARDWAREID, NULL, (PBYTE)buf, sizeof(buf), NULL)) {
            m.hwID = buf; 
            if (m.hwID.find(L"VID_") != std::wstring::npos) {
                lista.push_back(m);
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return lista;
}

// --- MAIN ---

int main() {
    _wsetlocale(LC_ALL, L"");

    // CARGAR CONFIGURACIÓN HISTÓRICA ANTES DE TOCAR EL DRIVER
    CargarConfiguracionLocal();

    // Intentar buscar si el proceso objetivo guardado ya está corriendo para extraer su PID
    DWORD pidAuto = ObtenerPIDPorNombre(g_exeTarget);
    if (pidAuto != 0) {
        g_whitelistPIDs.clear();
        g_whitelistPIDs.push_back(pidAuto);
    }

    // PASO 1: SELECCIÓN / CONFIRMACIÓN DE WHITELIST
    auto procesos = ListarProcesosUsuario();
    std::wcout << L"=== PASO 1: SELECCIONAR PROGRAMA PARA WHITELIST ===\n";
    
    if (!g_exeTarget.empty()) {
        std::wcout << L"[*] Objetivo persistente actual: " << g_exeTarget << L"\n";
        if (pidAuto != 0) {
            std::wcout << L"[OK] ¡El proceso está ACTIVO! (PID: " << pidAuto << L"). Se auto-autorizará.\n\n";
        } else {
            std::wcout << L"[!] El proceso NO está abierto. Abre el emulador ahora si deseas asociarlo.\n\n";
        }
    }

    std::wcout << L"Lista de procesos activos (Usuario):\n";
    for (size_t i = 0; i < procesos.size(); i++) {
        std::wcout << (i + 1) << L". " << procesos[i].nombre << L"\t";
        if ((i + 1) % 3 == 0) std::wcout << L"\n";
    }
    
    std::wcout << L"\n\nOpciones de selección:\n";
    std::wcout << L" - Ingrese el NUMERO del proceso de la lista.\n";
    std::wcout << L" - Escriba 'm' para escribir el nombre del .exe manualmente.\n";
    std::wcout << L" - Ingrese '0' para continuar con el objetivo actual/omitir.\n";
    std::wcout << L"Seleccion: ";
    
    std::wstring selInput;
    std::wcin >> selInput;

    if (selInput == L"m" || selInput == L"M") {
        std::wcout << L"Ingrese el nombre exacto del ejecutable (ej: pcsx2.exe): ";
        std::wcin >> g_exeTarget;
        DWORD nuevoPid = ObtenerPIDPorNombre(g_exeTarget);
        g_whitelistPIDs.clear();
        if (nuevoPid != 0) {
            g_whitelistPIDs.push_back(nuevoPid);
            std::wcout << L"[OK] Vinculado a " << g_exeTarget << L" (PID: " << nuevoPid << L")\n";
        } else {
            std::wcout << L"[!] Guardado '" << g_exeTarget << L"' para persistencia (Actualmente cerrado).\n";
        }
        Sleep(1500);
    } else if (selInput != L"0") {
        try {
            int idx = std::stoi(selInput);
            if (idx > 0 && idx <= (int)procesos.size()) {
                g_exeTarget = procesos[idx - 1].nombre;
                g_whitelistPIDs.clear();
                g_whitelistPIDs.push_back(procesos[idx - 1].pid);
                std::wcout << L"\n[OK] " << g_exeTarget << L" (PID " << procesos[idx - 1].pid << L") añadido.\n";
                Sleep(1000);
            }
        } catch (...) {}
    }

    // Refrescar PID justo antes de aplicar por si el usuario abrió el juego en este lapso
    if (pidAuto == 0 && !g_exeTarget.empty()) {
        DWORD pidFresco = ObtenerPIDPorNombre(g_exeTarget);
        if (pidFresco != 0) {
            g_whitelistPIDs.clear();
            g_whitelistPIDs.push_back(pidFresco);
        }
    }

    // Aplicar inmediatamente la combinación de bloqueos guardados + Whitelist del PID actual
    AplicarCambios();
    ReiniciarHID();

    // PASO 2: BUCLE DE GESTIÓN EN VIVO
    std::wstring input;
    while (true) {
        system("cls");
        std::wcout << L"=== PASO 2: GESTION DE DISPOSITIVOS (MandoShield) ===\n";
        std::wcout << L"Ejecutando con privilegios de Administrador.\n";
        std::wcout << L"Persistencia del ejecutable: " << (g_exeTarget.empty() ? L"Ninguno" : g_exeTarget) << L"\n";
        
        // Mostrar si el objetivo está vivo o muerto en tiempo real en el bucle
        DWORD pidBucle = ObtenerPIDPorNombre(g_exeTarget);
        if (!g_exeTarget.empty()) {
            if (pidBucle != 0) {
                std::wcout << L"Estado del objetivo: ACTIVO (PID: " << pidBucle << L") [PROTEGIDO]\n\n";
                // Si el juego se cerró y se volvió a abrir en caliente, actualizamos el PID en la whitelist de inmediato
                if (g_whitelistPIDs.empty() || g_whitelistPIDs[0] != pidBucle) {
                    g_whitelistPIDs.clear();
                    g_whitelistPIDs.push_back(pidBucle);
                    AplicarCambios();
                    ReiniciarHID();
                }
            } else {
                std::wcout << L"Estado del objetivo: INACTIVO (Cerrado)\n\n";
            }
        }

        auto mandos = ListarMandos();
        std::wcout << L"ID | ESTADO   | NOMBRE / HARDWARE ID\n";
        std::wcout << L"---|----------|------------------------------------\n";
        for (size_t i = 0; i < mandos.size(); i++) {
            bool b = std::find(g_bloqueados.begin(), g_bloqueados.end(), mandos[i].hwID) != g_bloqueados.end();
            std::wcout << i + 1 << L". [" << (b ? L"BLOQUEADO" : L" LIBRE   ") << L"] " << mandos[i].name << L"\n";
            std::wcout << L"   ID: " << mandos[i].hwID << L"\n\n";
        }

        std::wcout << L"OPCIONES:\n";
        std::wcout << L"- Ingrese numeros (ej: 1,2) para alternar el estado de bloqueo.\n";
        std::wcout << L"- [0] Salir MANTENIENDO la configuracion actual y bloqueos para el proximo inicio.\n";
        std::wcout << L"- [limpiar] Desbloquear todo por completo y borrar configuracion guardada.\n";
        std::wcout << L"Seleccion: ";
        
        std::wcin >> input;

        if (input == L"0") {
            std::wcout << L"\n[+] Configuracion retenida de forma segura. Saliendo...\n";
            break;
        }

        if (input == L"limpiar" || input == L"LIMPIAR") {
            g_bloqueados.clear();
            g_exeTarget = L"";
            g_whitelistPIDs.clear();
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, PATH_MANDOSHIELD);
            AplicarCambios();
            ReiniciarHID();
            std::wcout << L"\n[-] Todo el registro ha sido restaurado a por defecto. Saliendo...\n";
            Sleep(1500);
            break;
        }

        // Procesar múltiples selecciones de mandos
        std::wstringstream ss(input);
        std::wstring item;
        while (std::getline(ss, item, L',')) {
            try {
                int idx = std::stoi(item);
                if (idx > 0 && idx <= (int)mandos.size()) {
                    auto it = std::find(g_bloqueados.begin(), g_bloqueados.end(), mandos[idx - 1].hwID);
                    if (it != g_bloqueados.end()) {
                        g_bloqueados.erase(it);
                    } else {
                        g_bloqueados.push_back(mandos[idx - 1].hwID);
                    }
                }
            } catch (...) {}
        }

        if (!AplicarCambios()) {
            std::wcout << L"\n[!] ERROR: Error critico de escritura en el registro.\n";
            Sleep(2000);
        }
        
        ReiniciarHID();
        std::wcout << L"\n[*] Aplicando y sincronizando cambios...";
        Sleep(800);
    }

    return 0;
}
