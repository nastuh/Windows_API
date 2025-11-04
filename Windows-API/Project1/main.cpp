#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <lm.h>
#include <locale>
#include <codecvt>
#include <sddl.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

class SystemInfo {
private:
    LARGE_INTEGER frequency;
    LARGE_INTEGER startTime;
    LARGE_INTEGER endTime;

public:
    SystemInfo() {
        QueryPerformanceFrequency(&frequency);
    }

    void startTimer() {
        QueryPerformanceCounter(&startTime);
    }

    void stopTimer() {
        QueryPerformanceCounter(&endTime);
    }

    double getElapsedTimeMicroseconds() {
        return (endTime.QuadPart - startTime.QuadPart) * 1000000.0 / frequency.QuadPart;
    }

    // Задание 1: Получение информации о системе
    void getSystemInfo() {
        startTimer(); // Начало замера времени

        std::cout << "=== ИНФОРМАЦИЯ О СИСТЕМЕ И КОМПЬЮТЕРЕ ===\n" << std::endl;

        // 1) Версия операционной системы
        getOSVersion();

        // 2) Системный каталог
        getSystemDirectory();

        // 3) Расширенная информация о компьютере и пользователе
        getExtendedComputerAndUserInfo();

        // 4) Информация о томах
        getVolumeInfo();

        // 5) Программы, запускаемые при старте системы
        getStartupPrograms();

        stopTimer(); // Конец замера времени
    }

private:
    void getOSVersion() {
        std::cout << "1. ВЕРСИЯ ОПЕРАЦИОННОЙ СИСТЕМЫ:" << std::endl;

        HMODULE hModule = GetModuleHandle(TEXT("ntdll.dll"));
        if (hModule) {
            typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
            RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hModule, "RtlGetVersion");

            if (RtlGetVersion) {
                RTL_OSVERSIONINFOW osvi = { 0 };
                osvi.dwOSVersionInfoSize = sizeof(osvi);

                if (RtlGetVersion(&osvi) == 0) {
                    std::cout << "   Windows версия: " << osvi.dwMajorVersion << "."
                        << osvi.dwMinorVersion << std::endl;
                    std::cout << "   Build: " << osvi.dwBuildNumber << std::endl;
                    return;
                }
            }
        }

        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            DWORD majorVersion, minorVersion;
            DWORD size = sizeof(DWORD);

            if (RegQueryValueEx(hKey, TEXT("CurrentMajorVersionNumber"), NULL, NULL,
                (LPBYTE)&majorVersion, &size) == ERROR_SUCCESS) {
                RegQueryValueEx(hKey, TEXT("CurrentMinorVersionNumber"), NULL, NULL,
                    (LPBYTE)&minorVersion, &size);
                std::cout << "   Windows версия: " << majorVersion << "." << minorVersion << std::endl;
            }

            TCHAR buildStr[64];
            DWORD buildStrSize = sizeof(buildStr);
            if (RegQueryValueEx(hKey, TEXT("CurrentBuildNumber"), NULL, NULL,
                (LPBYTE)buildStr, &buildStrSize) == ERROR_SUCCESS) {
                std::wcout << L"   Build: " << buildStr << std::endl;
            }

            TCHAR productName[128];
            DWORD productNameSize = sizeof(productName);
            if (RegQueryValueEx(hKey, TEXT("ProductName"), NULL, NULL,
                (LPBYTE)productName, &productNameSize) == ERROR_SUCCESS) {
                std::wcout << L"   Продукт: " << productName << std::endl;
            }

            TCHAR edition[64];
            DWORD editionSize = sizeof(edition);
            if (RegQueryValueEx(hKey, TEXT("EditionID"), NULL, NULL,
                (LPBYTE)edition, &editionSize) == ERROR_SUCCESS) {
                std::wcout << L"   Редакция: " << edition << std::endl;
            }

            TCHAR installDate[64];
            DWORD installDateSize = sizeof(installDate);
            if (RegQueryValueEx(hKey, TEXT("InstallDate"), NULL, NULL,
                (LPBYTE)installDate, &installDateSize) == ERROR_SUCCESS) {
                DWORD installTimestamp = *reinterpret_cast<DWORD*>(installDate);
                time_t installTime = installTimestamp;
                struct tm timeinfo;
                localtime_s(&timeinfo, &installTime);
                char buffer[80];
                strftime(buffer, sizeof(buffer), "%d.%m.%Y %H:%M:%S", &timeinfo);
                std::cout << "   - Дата установки: " << buffer << std::endl;
            }

            RegCloseKey(hKey);
        }
        else {
            std::cout << "   Не удалось получить информацию о версии ОС" << std::endl;
        }
        std::cout << std::endl;
    }

    void getSystemDirectory() {
        std::cout << "2. СИСТЕМНЫЙ КАТАЛОГ:" << std::endl;

        TCHAR systemDir[MAX_PATH];
        UINT result = GetSystemDirectory(systemDir, MAX_PATH);

        if (result > 0) {
            std::wcout << L"   " << systemDir << std::endl;
        }
        else {
            std::cout << "   Не удалось получить системный каталог" << std::endl;
        }

        // Каталог Windows
        TCHAR windowsDir[MAX_PATH];
        if (GetWindowsDirectory(windowsDir, MAX_PATH)) {
            std::wcout << L"   - Каталог Windows: " << windowsDir << std::endl;
        }

        // Каталог временных файлов системы
        TCHAR tempDir[MAX_PATH];
        if (GetTempPath(MAX_PATH, tempDir)) {
            std::wcout << L"   - Каталог временных файлов: " << tempDir << std::endl;
        }
        std::cout << std::endl;
    }

    void getExtendedComputerAndUserInfo() {
        std::cout << "3. РАСШИРЕННАЯ ИНФОРМАЦИЯ О КОМПЬЮТЕРЕ И ПОЛЬЗОВАТЕЛЕ:" << std::endl;

        // Базовая информация о компьютере
        getBasicComputerInfo();

        // Информация о системе
        getSystemInfoDetails();

        // Информация о пользователе
        getUserInfoDetails();

        // Информация о домене/рабочей группе
        getDomainInfo();

        // Информация о времени работы системы
        getSystemUptime();

        // Информация о BIOS
        getBiosInfo();

        std::cout << std::endl;
    }

    void getBasicComputerInfo() {
        std::cout << "   ОСНОВНАЯ ИНФОРМАЦИЯ:" << std::endl;

        // Название компьютера
        TCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

        if (GetComputerName(computerName, &size)) {
            std::wcout << L"   - Имя компьютера: " << computerName << std::endl;
        }

        // Имя пользователя
        TCHAR userName[256];
        DWORD userNameSize = 256;

        if (GetUserName(userName, &userNameSize)) {
            std::wcout << L"   - Текущий пользователь: " << userName << std::endl;
        }

        // Имя компьютера (полное)
        TCHAR computerNameEx[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD computerNameExSize = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, computerNameEx, &computerNameExSize)) {
            std::wcout << L"   - Полное имя компьютера: " << computerNameEx << std::endl;
        }

        // Имя компьютера (NetBIOS)
        TCHAR computerNameNetBIOS[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD computerNameNetBIOSSize = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameEx(ComputerNameNetBIOS, computerNameNetBIOS, &computerNameNetBIOSSize)) {
            std::wcout << L"   - Имя NetBIOS: " << computerNameNetBIOS << std::endl;
        }
    }

    void getSystemInfoDetails() {
        std::cout << "   СИСТЕМНАЯ ИНФОРМАЦИЯ:" << std::endl;

        // Архитектура процессора
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        std::cout << "   - Архитектура процессора: ";
        switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            std::cout << "x64" << std::endl;
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            std::cout << "ARM" << std::endl;
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            std::cout << "ARM64" << std::endl;
            break;
        case PROCESSOR_ARCHITECTURE_IA64:
            std::cout << "Itanium" << std::endl;
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            std::cout << "x86" << std::endl;
            break;
        default:
            std::cout << "Неизвестно" << std::endl;
        }

        std::cout << "   - Количество процессоров: " << sysInfo.dwNumberOfProcessors << std::endl;
        std::cout << "   - Размер страницы: " << sysInfo.dwPageSize << " байт" << std::endl;
        std::cout << "   - Минимальный адрес приложения: 0x" << std::hex << sysInfo.lpMinimumApplicationAddress << std::dec << std::endl;
        std::cout << "   - Максимальный адрес приложения: 0x" << std::hex << sysInfo.lpMaximumApplicationAddress << std::dec << std::endl;

        // Информация о памяти
        MEMORYSTATUSEX memoryStatus;
        memoryStatus.dwLength = sizeof(memoryStatus);
        if (GlobalMemoryStatusEx(&memoryStatus)) {
            std::cout << "   - Всего физической памяти: " << formatBytes(memoryStatus.ullTotalPhys) << std::endl;
            std::cout << "   - Доступно физической памяти: " << formatBytes(memoryStatus.ullAvailPhys) << std::endl;
            std::cout << "   - Всего виртуальной памяти: " << formatBytes(memoryStatus.ullTotalVirtual) << std::endl;
            std::cout << "   - Доступно виртуальной памяти: " << formatBytes(memoryStatus.ullAvailVirtual) << std::endl;
            std::cout << "   - Загрузка памяти: " << memoryStatus.dwMemoryLoad << "%" << std::endl;
        }
    }

    void getUserInfoDetails() {
        std::cout << "   ИНФОРМАЦИЯ О ПОЛЬЗОВАТЕЛЕ:" << std::endl;

        // SID пользователя
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD tokenInfoLength = 0;
            GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);

            if (tokenInfoLength > 0) {
                PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, tokenInfoLength);
                if (GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoLength, &tokenInfoLength)) {
                    LPWSTR userSID = NULL;
                    if (ConvertSidToStringSidW(pTokenUser->User.Sid, &userSID)) {
                        std::wcout << L"   - SID пользователя: " << userSID << std::endl;
                        LocalFree(userSID);
                    }
                }
                LocalFree(pTokenUser);
            }
            CloseHandle(hToken);
        }

        // Домашний каталог пользователя
        TCHAR userProfile[MAX_PATH];
        DWORD userProfileSize = MAX_PATH;
        if (GetEnvironmentVariable(TEXT("USERPROFILE"), userProfile, userProfileSize)) {
            std::wcout << L"   - Домашний каталог: " << userProfile << std::endl;
        }

        // Каталог временных файлов
        TCHAR tempPath[MAX_PATH];
        if (GetTempPath(MAX_PATH, tempPath)) {
            std::wcout << L"   - Каталог временных файлов: " << tempPath << std::endl;
        }

        // Права администратора
        BOOL isAdmin = FALSE;
        HANDLE hToken2;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken2)) {
            TOKEN_ELEVATION elevation;
            DWORD dwSize;
            if (GetTokenInformation(hToken2, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
            CloseHandle(hToken2);
        }
        std::cout << "   - Права администратора: " << (isAdmin ? "Да" : "Нет") << std::endl;

        // Дополнительная информация о пользователе
        TCHAR userDomain[256];
        DWORD userDomainSize = 256;
        if (GetEnvironmentVariable(TEXT("USERDOMAIN"), userDomain, userDomainSize)) {
            std::wcout << L"   - Домен пользователя: " << userDomain << std::endl;
        }

        TCHAR userHomeDrive[MAX_PATH];
        DWORD userHomeDriveSize = MAX_PATH;
        if (GetEnvironmentVariable(TEXT("HOMEDRIVE"), userHomeDrive, userHomeDriveSize)) {
            std::wcout << L"   - Домашний диск: " << userHomeDrive << std::endl;
        }

        // Информация о сессии пользователя
        DWORD sessionId;
        if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
            std::cout << "   - ID сессии: " << sessionId << std::endl;
        }
    }

    void getDomainInfo() {
        std::cout << "   СЕТЕВАЯ ИНФОРМАЦИЯ:" << std::endl;

        // Имя домена/рабочей группы
        TCHAR domainName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD domainNameSize = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameEx(ComputerNamePhysicalDnsDomain, domainName, &domainNameSize)) {
            if (wcslen(domainName) > 0) {
                std::wcout << L"   - Домен: " << domainName << std::endl;
            }
            else {
                std::cout << "   - Рабочая группа: WORKGROUP" << std::endl;
            }
        }

        // Информация о домене через NetAPI
        LPWSTR domainController = NULL;
        NET_API_STATUS status = NetGetDCName(NULL, NULL, (LPBYTE*)&domainController);
        if (status == NERR_Success) {
            std::wcout << L"   - Контроллер домена: " << domainController << std::endl;
            NetApiBufferFree(domainController);
        }

        // Информация о сетевых адаптерах через реестр
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            TEXT("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"),
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subkeyCount;
            if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &subkeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                std::cout << "   - Количество сетевых интерфейсов: " << subkeyCount << std::endl;
            }
            RegCloseKey(hKey);
        }
    }

    void getSystemUptime() {
        std::cout << "   ВРЕМЯ РАБОТЫ СИСТЕМЫ:" << std::endl;

        ULONGLONG uptimeMs = GetTickCount64();
        ULONGLONG days = uptimeMs / (1000 * 60 * 60 * 24);
        ULONGLONG hours = (uptimeMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60);
        ULONGLONG minutes = (uptimeMs % (1000 * 60 * 60)) / (1000 * 60);
        ULONGLONG seconds = (uptimeMs % (1000 * 60)) / 1000;

        std::cout << "   - Система работает: " << days << " дней, "
            << hours << " часов, " << minutes << " минут, "
            << seconds << " секунд" << std::endl;

        // Время последней перезагрузки
        FILETIME ftBoot, ftNow;
        ULARGE_INTEGER uiBoot, uiNow;
        SYSTEMTIME stBoot;

        GetSystemTimeAsFileTime(&ftNow);
        uiNow.LowPart = ftNow.dwLowDateTime;
        uiNow.HighPart = ftNow.dwHighDateTime;

        if (GetTickCount64() != 0) {
            uiBoot.QuadPart = uiNow.QuadPart - (GetTickCount64() * 10000);
            ftBoot.dwLowDateTime = uiBoot.LowPart;
            ftBoot.dwHighDateTime = uiBoot.HighPart;

            if (FileTimeToSystemTime(&ftBoot, &stBoot)) {
                std::cout << "   - Последняя перезагрузка: "
                    << stBoot.wDay << "." << stBoot.wMonth << "." << stBoot.wYear
                    << " " << stBoot.wHour << ":" << stBoot.wMinute << ":" << stBoot.wSecond << std::endl;
            }
        }
    }

    void getBiosInfo() {
        std::cout << "   ИНФОРМАЦИЯ О BIOS:" << std::endl;

        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            TEXT("HARDWARE\\DESCRIPTION\\System\\BIOS"),
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            TCHAR biosVendor[256];
            DWORD biosVendorSize = sizeof(biosVendor);
            if (RegQueryValueEx(hKey, TEXT("BIOSVendor"), NULL, NULL,
                (LPBYTE)biosVendor, &biosVendorSize) == ERROR_SUCCESS) {
                std::wcout << L"   - Производитель BIOS: " << biosVendor << std::endl;
            }

            TCHAR biosVersion[256];
            DWORD biosVersionSize = sizeof(biosVersion);
            if (RegQueryValueEx(hKey, TEXT("BIOSVersion"), NULL, NULL,
                (LPBYTE)biosVersion, &biosVersionSize) == ERROR_SUCCESS) {
                std::wcout << L"   - Версия BIOS: " << biosVersion << std::endl;
            }

            TCHAR biosReleaseDate[256];
            DWORD biosReleaseDateSize = sizeof(biosReleaseDate);
            if (RegQueryValueEx(hKey, TEXT("BIOSReleaseDate"), NULL, NULL,
                (LPBYTE)biosReleaseDate, &biosReleaseDateSize) == ERROR_SUCCESS) {
                std::wcout << L"   - Дата BIOS: " << biosReleaseDate << std::endl;
            }

            RegCloseKey(hKey);
        }
    }

    void getVolumeInfo() {
        std::cout << "4. ИНФОРМАЦИЯ О ТОМАХ:" << std::endl;

        TCHAR volumeName[MAX_PATH];
        HANDLE hFind = FindFirstVolume(volumeName, MAX_PATH);

        if (hFind == INVALID_HANDLE_VALUE) {
            std::cout << "   Не удалось найти тома" << std::endl;
            return;
        }

        int volumeCount = 0;
        do {
            volumeCount++;
            std::wcout << L"   Том " << volumeCount << ":" << std::endl;
            std::wcout << L"   - Служебное имя: " << volumeName << std::endl;

            // Получение пути тома
            TCHAR volumePath[MAX_PATH];
            DWORD bufferLength = MAX_PATH;

            if (GetVolumePathNamesForVolumeName(volumeName, volumePath, bufferLength, &bufferLength) && bufferLength > 0) {
                std::wcout << L"   - Путь в файловой системе: " << volumePath << std::endl;

                // Получение информации о свободном месте
                ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;

                if (GetDiskFreeSpaceEx(volumePath, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
                    std::cout << "   - Общий объем: " << formatBytes(totalNumberOfBytes.QuadPart) << std::endl;
                    std::cout << "   - Свободное место: " << formatBytes(freeBytesAvailable.QuadPart) << std::endl;

                    double freePercentage = (double)freeBytesAvailable.QuadPart / totalNumberOfBytes.QuadPart * 100;
                    std::cout << "   - Свободно: " << std::fixed << std::setprecision(1) << freePercentage << "%" << std::endl;

                    // Информация о файловой системе
                    TCHAR fileSystemName[MAX_PATH];
                    TCHAR volumeLabel[MAX_PATH];
                    DWORD serialNumber, maxComponentLength, fileSystemFlags;
                    if (GetVolumeInformation(volumePath, volumeLabel, MAX_PATH, &serialNumber,
                        &maxComponentLength, &fileSystemFlags, fileSystemName, MAX_PATH)) {
                        std::wcout << L"   - Файловая система: " << fileSystemName << std::endl;
                        if (wcslen(volumeLabel) > 0) {
                            std::wcout << L"   - Метка тома: " << volumeLabel << std::endl;
                        }
                        std::cout << "   - Серийный номер тома: " << std::hex << serialNumber << std::dec << std::endl;
                        std::cout << "   - Макс. длина имени файла: " << maxComponentLength << " символов" << std::endl;

                        // Флаги файловой системы (используем только стандартные константы)
                        std::cout << "   - Флаги файловой системы: ";
                        if (fileSystemFlags & FILE_VOLUME_IS_COMPRESSED) std::cout << "Сжатый том ";
                        if (fileSystemFlags & FILE_READ_ONLY_VOLUME) std::cout << "Только чтение ";
                        if (fileSystemFlags & FILE_SUPPORTS_REPARSE_POINTS) std::cout << "Точки повторного анализа ";
                        if (fileSystemFlags & FILE_SUPPORTS_SPARSE_FILES) std::cout << "Разреженные файлы ";
                        if (fileSystemFlags & FILE_SUPPORTS_REMOTE_STORAGE) std::cout << "Удаленное хранилище ";
                        if (fileSystemFlags & FILE_NAMED_STREAMS) std::cout << "Именованные потоки ";
                        std::cout << std::endl;
                    }
                }
                else {
                    std::cout << "   - Информация о дисковом пространстве: не доступна" << std::endl;
                }
            }
            else {
                std::wcout << L"   - Путь в файловой системе: не доступен" << std::endl;
            }

            std::cout << std::endl;

        } while (FindNextVolume(hFind, volumeName, MAX_PATH));

        FindVolumeClose(hFind);

        if (volumeCount == 0) {
            std::cout << "   Тома не найдены" << std::endl;
        }
    }

    void getStartupPrograms() {
        std::cout << "5. ПРОГРАММЫ, ЗАПУСКАЕМЫЕ ПРИ СТАРТЕ СИСТЕМЫ:" << std::endl;

        HKEY hKey;
        LONG result = RegOpenKeyEx(HKEY_CURRENT_USER,
            TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            0, KEY_READ, &hKey);

        if (result != ERROR_SUCCESS) {
            std::cout << "   Не удалось открыть раздел реестра" << std::endl;
            return;
        }

        DWORD index = 0;
        TCHAR valueName[256];
        DWORD valueNameSize = 256;
        BYTE data[1024];
        DWORD dataSize = 1024;
        DWORD type;

        int programCount = 0;

        while (true) {
            valueNameSize = 256;
            dataSize = 1024;

            result = RegEnumValue(hKey, index, valueName, &valueNameSize,
                NULL, &type, data, &dataSize);

            if (result == ERROR_NO_MORE_ITEMS) {
                break;
            }

            if (result == ERROR_SUCCESS) {
                programCount++;
                std::wcout << L"   " << programCount << ". " << valueName << L": ";

                if (type == REG_SZ) {
                    std::wcout << reinterpret_cast<wchar_t*>(data);
                }
                else if (type == REG_EXPAND_SZ) {
                    TCHAR expandedPath[MAX_PATH];
                    ExpandEnvironmentStrings(reinterpret_cast<TCHAR*>(data), expandedPath, MAX_PATH);
                    std::wcout << expandedPath;
                }
                else {
                    std::wcout << L"(тип данных: " << type << L")";
                }
                std::wcout << std::endl;
            }

            index++;
        }

        RegCloseKey(hKey);

        if (programCount == 0) {
            std::cout << "   Программы для автозагрузки не найдены" << std::endl;
        }
        std::cout << std::endl;
    }

    std::string formatBytes(ULONGLONG bytes) {
        const char* suffixes[] = { "Б", "КБ", "МБ", "ГБ", "ТБ" };
        int suffixIndex = 0;
        double size = static_cast<double>(bytes);

        while (size >= 1024 && suffixIndex < 4) {
            size /= 1024;
            suffixIndex++;
        }

        std::ostringstream stream;
        stream << std::fixed << std::setprecision(2) << size << " " << suffixes[suffixIndex];
        return stream.str();
    }

public:
    // Задание 2: Вывод информации о производительности
    void printPerformanceInfo() {
        std::cout << "=== ИНФОРМАЦИЯ О ПРОИЗВОДИТЕЛЬНОСТИ ===" << std::endl;
        std::cout << "Частота ЦП: " << frequency.QuadPart << " тактов/сек" << std::endl;
        std::cout << "Время выполнения сбора системной информации: "
            << std::fixed << std::setprecision(2) << getElapsedTimeMicroseconds()
            << " мкс" << std::endl;
    }
};

int main() {
    // Устанавливаем кодировку для корректного отображения русского текста
    SetConsoleOutputCP(1251);
    SetConsoleCP(1251);

    SystemInfo systemInfo;

    std::cout << "Лабораторная работа: Определение параметров системы и компьютера\n" << std::endl;

    // Выполнение задания 1
    systemInfo.getSystemInfo();

    // Выполнение задания 2
    systemInfo.printPerformanceInfo();

    std::cout << "\nНажмите Enter для выхода...";
    std::cin.get();

    return 0;
}
