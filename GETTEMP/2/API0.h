#pragma once

#include <iostream>
#include <windows.h>
#include <vector>
#include <wincrypt.h>
#include <tchar.h>
#include <string>
#include <tlhelp32.h>
#include <fstream>
#include <float.h>
#include <ctime>
#include <intrin.h>
#include <filesystem>
#include <cstdlib>
#include <cstdint>
#include <sddl.h>
#include <aclapi.h>
#include <mutex>
#include <shlwapi.h>     // <- thay cho pathcch.h
#include "DRIVERS.h"

#pragma comment(lib, "Shlwapi.lib") 
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
typedef BOOL (*InitializeOls)();
typedef BOOL (*DeinitializeOls)();
typedef BOOL (*Rdmsr)(DWORD, DWORD*, DWORD*);
typedef NTSTATUS (NTAPI* pNtTerminateProcess)(HANDLE, NTSTATUS);

using namespace std;
namespace fs = std::filesystem;
inline int Tlog = 0, UseSysTime = 0, NoDTime = 0, Install = 0, Unins = 0, SYSTEM = 0;
inline long double total = 0.0, countNum = 1.0, Avg = 0;
inline time_t startTime; 
inline string WinRing0x64 = "WinRing0x64.dll", WinRing0x64D = "WinRing0x64.sys", CER="C:/Windows/System32/vmultra.cer", CER1="C:/Windows/System32/Vien_Minh.cer";
inline const char* ROOT_CER = "Root";
inline const char* TRUSTED_CER = "TrustedPublisher";
inline const char* CER_PATH = "C:/Windows/System32/vmultra.cer";
inline const char* CER_PATH1 = "C:/Windows/System32/Vien_Minh.cer";
inline const char* INSTALL_PATH = "C:/Windows/System32/gettemp.exe";

namespace std{
    // Read CPUID leaf and subleaf
    static void GetCpuid(uint32_t leaf, uint32_t subleaf, uint32_t out[4]) {
        __cpuidex(reinterpret_cast<int*>(out), leaf, subleaf);
    }

    //Error
    std::wstring& get_program_name(const char* argv0 = nullptr) {
        static std::wstring name;
        static std::once_flag flag;

        std::call_once(flag, [&]() {
            int len = MultiByteToWideChar(CP_UTF8, 0, argv0, -1, nullptr, 0);
            name.resize(len);
            MultiByteToWideChar(CP_UTF8, 0, argv0, -1, &name[0], len);
        });

        return name;
    }
    //

    
    std::wstring GetExeName() {
        wchar_t buf[MAX_PATH];
        DWORD len = GetModuleFileNameW(NULL, buf, MAX_PATH);
        if (len == 0 || len == MAX_PATH) return L"";

        PCWSTR filePart = PathFindFileNameW(buf);
        return std::wstring(filePart);
    }
    std::wstring GetExeNameNew() {
        wchar_t buf[MAX_PATH];
        GetModuleFileNameW(NULL, buf, MAX_PATH);
        std::wstring fullPath(buf);
        size_t pos = fullPath.find_last_of(L"\\\\/");
        return (pos != std::wstring::npos) ? fullPath.substr(pos + 1) : fullPath;
    }


    PCCERT_CONTEXT LoadCertificateFromFile(const char* filePath) {
    // Mở file ở chế độ binary và con trỏ ở cuối để biết size
    ifstream file(filePath, ios::binary | ios::ate);
    if (!file.is_open()) {
        return nullptr;
    }

    // Lấy kích thước file
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    // Đọc toàn bộ nội dung file vào buffer
    vector<BYTE> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return nullptr;
    }

    const BYTE* pbCertEncoded = buffer.data();
    DWORD cbCertEncoded = static_cast<DWORD>(buffer.size());

    // Tạo PCCERT_CONTEXT từ dữ liệu DER vừa load
    PCCERT_CONTEXT pCert = CertCreateCertificateContext(
    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, // Encoding types
    pbCertEncoded,                           // Pointer to encoded cert
    cbCertEncoded                            // Size in bytes of encoded cert
    );

    return pCert; // NULL nếu không tạo được
}

    // Kiểm tra xem certificate pCertToCheck có nằm trong store (LocalMachine\<storeName>) hay không
    bool IsCertInStore(const char* storeName, PCCERT_CONTEXT pCertToCheck) {
        if (pCertToCheck == nullptr) {
            return false;
        }

        // Mở store hệ thống (Local Machine)
        HCERTSTORE hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,       // provider kiểu ANSI
            0,                              // dwEncodingType, với CERT_STORE_PROV_SYSTEM thì để 0
            (HCRYPTPROV_LEGACY)0,           // hCryptProv, không dùng nên để NULL hoặc 0
            CERT_SYSTEM_STORE_LOCAL_MACHINE,// flags: mở store ở LocalMachine
            storeName                       // tên store (ví dụ: "ROOT", "MY", "CA", …)
        );

        if (!hStore) {
            return false;
        }

        PCCERT_CONTEXT pCertInStore = nullptr;
        bool found = false;

        // Duyệt qua các certificate trong store
        while ((pCertInStore = CertEnumCertificatesInStore(hStore, pCertInStore)) != nullptr) {
            // So sánh pCertToCheck vs certificate đang xét (theo toàn bộ CERT_INFO)
            if (CertCompareCertificate(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    pCertToCheck->pCertInfo,
                    pCertInStore->pCertInfo))
            {
                found = true;
                break;
            }
        }

        CertCloseStore(hStore, 0);
        return found;
    }
    
    bool RunCmdHidden(const std::wstring& cmdLine)
    {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        // Đặt để ẩn cửa sổ
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        // Tạo process ẩn
        BOOL result = CreateProcessW(
            nullptr,               // ứng dụng (sẽ chạy cmd.exe nên để nullptr)
            const_cast<LPWSTR>(cmdLine.c_str()), // command line
            nullptr,               // security attributes process
            nullptr,               // security attributes thread
            FALSE,                 // không kế thừa handle
            CREATE_NO_WINDOW,      // flag tạo process ẩn cửa sổ
            nullptr,               // environment
            nullptr,               // current directory
            &si,
            &pi);

        if (!result)
        {
            // Tạo process thất bại
            return false;
        }

        // Đợi process kết thúc (có thể bỏ nếu muốn chạy ngầm hoàn toàn)
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Đóng handle
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return true;
    }

    bool SetPrivilege(LPCSTR privName, bool enable)
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                              &hToken))
        {
            return false;
        }

        TOKEN_PRIVILEGES tp{};
        LUID luid;
        // Dùng LookupPrivilegeValueA vì privName là ANSI
        if (!LookupPrivilegeValueA(nullptr, privName, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) ||
            GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        {
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return true;
    }
    
    bool CreateRegKey(
    HKEY hRoot,
    const std::wstring& keyPath,
    const std::wstring& valueName,
    DWORD valueType,
    const BYTE* data,
    DWORD dataSize,
    bool hiddenStatus)
    {
        HKEY hKey = NULL;
        DWORD dwDisposition = 0;

        // Mở hoặc tạo key
        LSTATUS status = RegCreateKeyExW(
            hRoot,
            keyPath.c_str(),
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | WRITE_DAC,
            NULL,
            &hKey,
            &dwDisposition
        );
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"RegCreateKeyExW failed with code: " << status << std::endl;
            return false;
        }

        // Ghi giá trị vào key
        status = RegSetValueExW(
            hKey,
            valueName.c_str(),
            0,
            valueType,
            data,
            dataSize
        );
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"RegSetValueExW failed with code: " << status << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        // Nếu cần ẩn key bằng DACL
        if (hiddenStatus) {
            LPCWSTR sddl = L"D:(D;;KA;;;WD)(A;;GA;;;SY)(D;;KA;;;BA)";
            PSECURITY_DESCRIPTOR pSD = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl,
                    SDDL_REVISION_1,
                    &pSD,
                    nullptr))
            {
                // Nhúng DACL mới vào key
                BOOL daclPresent = FALSE;
                PACL pDacl = nullptr;
                BOOL daclDefaulted = FALSE;
                if (!GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted)) {
                    std::wcerr << L"GetSecurityDescriptorDacl failed: " << GetLastError() << std::endl;
                }
                else {
                    status = SetSecurityInfo(
                        hKey,
                        SE_REGISTRY_KEY,
                        DACL_SECURITY_INFORMATION,
                        nullptr,        // không thay đổi owner
                        nullptr,        // không thay đổi group
                        pDacl,          // dùng DACL vừa lấy
                        nullptr         // không quan tâm SACL
                    );
                    if (status != ERROR_SUCCESS) {
                        std::wcerr << L"SetSecurityInfo failed with code: " << status << std::endl;
                    }
                }
                LocalFree(pSD);
            } else {
                std::wcerr << L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed with code: " 
                           << GetLastError() << std::endl;
            }
        }

        RegCloseKey(hKey);
        return true;
    }


    bool ReadRegKey(HKEY hRoot,
                const std::wstring& keyPath,
                const std::wstring& valueName,
                DWORD& outType,
                BYTE* outData,
                DWORD& inOutDataSize)
    {
        HKEY hKey = nullptr;
        LSTATUS status;

        // 1) Thử mở key với quyền đọc thông thường
        status = RegOpenKeyExW(
            hRoot,
            keyPath.c_str(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hKey
        );

        if (status != ERROR_SUCCESS) {
            // Nếu bị Access Denied, thử bật SeBackupPrivilege (ANSI)
            if (status == ERROR_ACCESS_DENIED) {
                if (SetPrivilege(SE_BACKUP_NAME, true)) {
                    status = RegOpenKeyExW(
                        hRoot,
                        keyPath.c_str(),
                        0,
                        KEY_READ | KEY_WOW64_64KEY,
                        &hKey
                    );
                    // Tắt privilege ngay sau khi mở xong
                    SetPrivilege(SE_BACKUP_NAME, false);
                }
            }
            if (status != ERROR_SUCCESS) {
                std::wcerr << L"RegOpenKeyExW failed (" << status << L")\n";
                return false;
            }
        }

        // 2) Đọc value
        DWORD type = 0;
        DWORD dataSize = inOutDataSize;
        status = RegQueryValueExW(
            hKey,
            valueName.c_str(),
            nullptr,
            &type,
            outData,
            &dataSize
        );
        RegCloseKey(hKey);

        if (status != ERROR_SUCCESS) {
            std::wcerr << L"RegQueryValueExW failed (" << status << L")\n";
            return false;
        }

        // 3) Trả về
        outType = type;
        inOutDataSize = dataSize;
        return true;
    }

    DWORD GetProcessIDByName(const wchar_t* procName) {
        PROCESSENTRY32W pe32{ sizeof(pe32) };
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return 0;
        if (Process32FirstW(hSnap, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, procName) == 0) {
                    CloseHandle(hSnap);
                    return pe32.th32ProcessID;
                }
            } while (Process32NextW(hSnap, &pe32));
        }
        CloseHandle(hSnap);
        return 0;
    }

    BOOL EnablePrivilege(LPCWSTR privName) {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return FALSE;
        TOKEN_PRIVILEGES tp{};
        LUID luid;
        if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
            CloseHandle(hToken);
            return FALSE;
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
        return ok && GetLastError() == ERROR_SUCCESS;
    }

    bool AccessSystemP(const std::wstring& programPath) {
        if (!EnablePrivilege(L"SeDebugPrivilege")) {
            return false;
        }

        DWORD pid = GetProcessIDByName(L"winlogon.exe");
        if (!pid) {
            return false;
        }

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) {
            return false;
        }

        HANDLE hSystemToken = NULL;
        if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hSystemToken)) {
            CloseHandle(hProc);
            return false;
        }

        HANDLE hDupToken = NULL;
        if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL,
                              SecurityImpersonation, TokenPrimary, &hDupToken)) {
            CloseHandle(hSystemToken);
            CloseHandle(hProc);
            return false;
        }

        STARTUPINFOW si{ sizeof(si) };
        PROCESS_INFORMATION pi{};
        if (!CreateProcessWithTokenW(
                hDupToken, 0,
                const_cast<LPWSTR>(programPath.c_str()),
                NULL,
                CREATE_NEW_CONSOLE,
                NULL, NULL,
                &si, &pi)) {
            CloseHandle(hDupToken);
            CloseHandle(hSystemToken);
            CloseHandle(hProc);
            return false;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hDupToken);
        CloseHandle(hSystemToken);
        CloseHandle(hProc);

        return true;
    }

    bool WriteArray(unsigned char INPUT[], long long bytesA, const wchar_t* PathW) {
        FILE* OUTPUT_FILE = _wfopen(PathW, L"wb");

        if (OUTPUT_FILE == NULL) {
            OutputDebugStringA("WriteArray failed!\n");
            return false;
        }

        size_t bytes_written = fwrite(INPUT, 1, bytesA, OUTPUT_FILE);

        fclose(OUTPUT_FILE);

        if (bytes_written == bytesA) {
            return true;
        } else {
                return false;
            }
    }

    bool WriteFile(unsigned char DATA[], long long bytes, const wchar_t* Path, DWORD Attribute, bool exist_test, bool write_exist) {
        if (exist_test) {
            if (!fs::exists(Path)) {
                    if (!WriteArray(DATA, bytes, Path)) return false;
                    SetFileAttributesW(Path, Attribute);
                
            } else {
                // Logic khi tệp đã tồn tại và exist_test là true
                // Hiện tại, nếu tệp đã tồn tại, hàm sẽ không ghi gì cả
                // và chỉ in ra thông báo. Nếu muốn ghi đè, cần thêm logic ở đây.
                if (write_exist) {
                    if (!WriteArray(DATA, bytes, Path)) return false;
                    SetFileAttributesW(Path, Attribute);
                }
            }
        } else {
            if (!WriteArray(DATA, bytes, Path)) return false;
            SetFileAttributesW(Path, Attribute);
        }
        return true;
    }

    // Kiểm tra membership well-known SID
    bool IsCurrentTokenInGroup(WELL_KNOWN_SID_TYPE sidType)
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            return false;
        }

        BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
        DWORD sidSize = sizeof(sidBuffer);
        BOOL isMember = FALSE;

        if (CreateWellKnownSid(sidType, nullptr, sidBuffer, &sidSize))
        {
            if (!CheckTokenMembership(hToken, sidBuffer, &isMember))
            {
            }
        }
        else
        {
        }

        CloseHandle(hToken);
        return isMember == TRUE;
    }

    // Kiểm tra token đã elevated (Admin) chưa
    bool IsProcessElevated()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            return false;
        }

        TOKEN_ELEVATION elevation;
        DWORD retLen = 0;
        bool elevated = false;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &retLen))
        {
            elevated = (elevation.TokenIsElevated != 0);
        }
        else
        {
        }
        CloseHandle(hToken);
        return elevated;
    }
    bool IsCurrentTokenSystem() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return false;
        }

        BYTE userSid[SECURITY_MAX_SID_SIZE];
        DWORD userSidSize = sizeof(userSid);
        TOKEN_USER* pTokenUser = (TOKEN_USER*)userSid;
        if (!GetTokenInformation(hToken, TokenUser, pTokenUser, userSidSize, &userSidSize)) {
            CloseHandle(hToken);
            return false;
        }

        BYTE systemSid[SECURITY_MAX_SID_SIZE];
        DWORD systemSidSize = sizeof(systemSid);
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSidSize)) {
            CloseHandle(hToken);
            return false;
        }

        bool isSystem = EqualSid(pTokenUser->User.Sid, systemSid);
        CloseHandle(hToken);
        return isSystem;
    }
    // In ra thông báo quyền với std::cout
    char PrintPrivilegeLevel()
    {
        if (IsCurrentTokenSystem())
        {
            return 0x00;
        }
        else if (IsProcessElevated())
        {
            return 0x01;
        }
        else if (IsCurrentTokenInGroup(WinAccountGuestSid))
        {
            return 0x03;
        }
        else
        {
            // Mọi trường hợp còn lại coi là Standard User
            return 0x02;
        }
    }

    bool DeleteFileSafe(const std::wstring& path) {
        if (DeleteFileW(path.c_str())) {
            //std::wcout << L"[✓] Đã xóa: " << path << L"\n";
            return true;
        } else {
            DWORD err = GetLastError();
            //std::wcerr << L"[!] Không xóa được " << path << L" (Lỗi " << err << L")\n";
            return false;
        }
    }

    bool KillProcessByName(const wchar_t* exeName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        TerminateProcess(hProcess, 1);
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return true;
    }

    bool KillProcessByPid(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) {
            return false;
        }

        BOOL result = TerminateProcess(hProcess, 1); // 1 = exit code
        CloseHandle(hProcess);
        return result == TRUE;
    }

    bool NtKillProcPid(DWORD pid) {
        // Load hàm NtTerminateProcess từ ntdll.dll
        pNtTerminateProcess NtTerminateProcess = (pNtTerminateProcess)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess");

        if (!NtTerminateProcess) {
            std::cerr << "Không tìm thấy NtTerminateProcess!\n";
            return false;
        }

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            std::cerr << "Không thể mở tiến trình PID: " << pid << "\n";
            return false;
        }

        NTSTATUS status = NtTerminateProcess(hProcess, 0); // 0 = exit code
        CloseHandle(hProcess);

        return (status == 0); // STATUS_SUCCESS = 0
    }
    bool NtKillProcName(const wchar_t* targetExeName) {
        // Load NtTerminateProcess
        pNtTerminateProcess NtTerminateProcess = (pNtTerminateProcess)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess");

        if (!NtTerminateProcess) {
            std::wcerr << L"Không tìm thấy NtTerminateProcess\n";
            return false;
        }

        // Tạo snapshot của các tiến trình đang chạy
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe32 = { sizeof(pe32) };

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, targetExeName) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        NTSTATUS status = NtTerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        CloseHandle(hSnapshot);
                        return (status == 0); // STATUS_SUCCESS
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return false;
    }

    inline std::wstring to_wstring(const std::string& str) {
        return std::wstring(str.begin(), str.end());
    }
    inline std::wstring to_wstring(const char* str) {
        return std::wstring(str, str + strlen(str));
    }
    inline const std::wstring& to_wstring(const std::wstring& wstr) {
        return wstr;
    }
    inline const std::wstring& to_wstring(const wchar_t* wstr) {
        return std::wstring(wstr); // caution: temp object!
    }

    bool CopyFileGeneric(const Path& src, const Path& dst) {
        std::ifstream in;
        std::ofstream out;

        std::wstring wsrc = to_wstring(src);
        std::wstring wdst = to_wstring(dst);

        in.open(wsrc, std::ios::binary);
        if (!in) return false;

        out.open(wdst, std::ios::binary);
        if (!out) return false;

        out << in.rdbuf();
        return true;
    }

    // Determine TjMax (°C) based on CPU vendor, family, and model
    float GetTjMaxByCPUID() {
        uint32_t cpuInfo[4] = {0};

        // Leaf 0: get vendor string parts
        GetCpuid(0, 0, cpuInfo);
        int maxLeaf = cpuInfo[0];
        char vendor[0x20] = {0};
        *reinterpret_cast<int*>(vendor) = cpuInfo[1];       // EBX
        *reinterpret_cast<int*>(vendor + 4) = cpuInfo[3];   // EDX
        *reinterpret_cast<int*>(vendor + 8) = cpuInfo[2];   // ECX

        // Leaf 1: get family and model
        GetCpuid(1, 0, cpuInfo);
        uint32_t eax = cpuInfo[0];
        uint32_t baseFamily   = (eax >> 8)  & 0xF;
        uint32_t baseModel    = (eax >> 4)  & 0xF;
        uint32_t extFamily    = (eax >> 20) & 0xFF;
        uint32_t extModelBits = (eax >> 16) & 0xF;

        uint32_t displayFamily = (baseFamily == 0xF) ? (baseFamily + extFamily) : baseFamily;
        uint32_t displayModel = ((baseFamily == 0x6) || (baseFamily == 0xF))
                                ? ((extModelBits << 4) + baseModel)
                                : baseModel;

        string vendorStr(vendor);

        // Intel CPU
        if (vendorStr == "GenuineIntel") {
            if (displayFamily == 6) {
                switch (displayModel) {
                    // Sandy Bridge
                    case 0x2A: case 0x2D:
                        return 100.0f;
                    // Ivy Bridge
                    case 0x3A: case 0x3E:
                        return 105.0f;
                    // Haswell
                    case 0x3C: case 0x3F: case 0x45: case 0x46:
                        return 100.0f;
                    // Broadwell
                    case 0x3D: case 0x47: case 0x4F: case 0x56:
                        return 100.0f;
                    // Skylake
                    case 0x4E: case 0x5E:
                        return 100.0f;
                    // Kaby Lake
                    case 0x8E: case 0x9E:
                        return 100.0f;
                    // Coffee Lake & Comet Lake
                    case 0xA5: case 0xA0:
                        return 100.0f;
                    // Rocket Lake
                    case 0x97:
                        return 100.0f;
                    // Alder Lake
                    case 0x9A:
                        return 100.0f;
                    // Raptor Lake
                    case 0xA7:
                        return 100.0f;
                    default:
                        return 100.0f; // default safe TjMax
                }
            }
            // Newer Intel families could be added here
            return 100.0f;
        }
        
        // AMD CPU
        if (vendorStr == "AuthenticAMD") {
            // Example mapping for AMD families
            if (displayFamily == 0x15) { // Bulldozer / Piledriver
                return 70.0f;
            }
            if (displayFamily == 0x16) { // Excavator
                return 95.0f;
            }
            if (displayFamily == 0x17) { // Zen / Zen+ / Zen2 / Zen3
                return 95.0f;
            }
            // Default for other AMD
            return 95.0f;
        }
        
        // Unknown vendor: return default
        return 100.0f;
    }

    // Read CPU temperature using WinRing0 (MSR IA32_THERM_STATUS)
    float GetCPUTemperature(HINSTANCE hDLL, InitializeOls init, DeinitializeOls deinit, Rdmsr rdmsr) {
        if (!init()) {
            cout << "Failed to initialize WinRing0. Error: " << GetLastError() << endl;
            return -1.0f;
        }

        DWORD eax = 0, edx = 0;
        const DWORD IA32_THERM_STATUS = 0x19C;
        BOOL success = rdmsr(IA32_THERM_STATUS, &eax, &edx);
        // Deinitialize regardless
        deinit();

        if (!success) {
            cout << "Failed to read MSR. Error: " << GetLastError() << endl;
            return -1.0f;
        }

        DWORD tempRaw = (eax >> 16) & 0x7F;
        if (tempRaw == 0) {
            cout << "Temperature reading invalid (0)." << endl;
            return -1.0f;
        }

        float tjMax = GetTjMaxByCPUID();
        return tjMax - static_cast<float>(tempRaw);
    }


    // Hàm lấy thời gian hệ thống
    string GetSystemTime() {
        time_t now = time(nullptr);
        struct tm* t = localtime(&now);
        char buffer[20];
        sprintf(buffer, "%02d:%02d:%02d:%02d", t->tm_yday, t->tm_hour, t->tm_min, t->tm_sec);
        return string(buffer);
    }

    // Hàm tính thời gian trôi qua từ khi bắt đầu
    string GetElapsedTime() {
        time_t now = time(nullptr);
        int elapsedSeconds = static_cast<int>(difftime(now, startTime));
        
        int days = elapsedSeconds / (24 * 3600);
        elapsedSeconds %= (24 * 3600);
        int hours = elapsedSeconds / 3600;
        elapsedSeconds %= 3600;
        int minutes = elapsedSeconds / 60;
        int seconds = elapsedSeconds % 60;

        char buffer[20];
        sprintf(buffer, "%02d:%02d:%02d:%02d", days, hours, minutes, seconds);
        return string(buffer);
    }

    void GetSystemInfo(float& minTemp, float& maxTemp, int Tlog, int UseSysTime, int NoDTime) {
        static HINSTANCE hDLL = LoadLibraryA("WinRing0x64.dll");
        static ofstream output;
        if (Tlog == 1 && !output.is_open()) {
            output.open("templog.log", ios::app);
            if (!output.is_open()) {
                cout << "Failed to open templog.log" << endl;
                return;
            }
        }

        if (!hDLL) {
            cout << "Could not load WinRing0x64.dll. Error: " << GetLastError() << endl;
            minTemp = maxTemp = -1.0f;
            return;
        }

        static InitializeOls init = (InitializeOls)GetProcAddress(hDLL, "InitializeOls");
        static DeinitializeOls deinit = (DeinitializeOls)GetProcAddress(hDLL, "DeinitializeOls");
        static Rdmsr rdmsr = (Rdmsr)GetProcAddress(hDLL, "Rdmsr");

        if (!init || !deinit || !rdmsr) {
            cout << "Could not find required functions in WinRing0x64.dll" << endl;
            FreeLibrary(hDLL);
            minTemp = maxTemp = -1.0f;
            return;
        }

        float temp = GetCPUTemperature(hDLL, init, deinit, rdmsr);
        if (temp != -1.0f) {
            if (temp < minTemp || minTemp == -1.0f) minTemp = temp;
            if (temp > maxTemp || maxTemp == -1.0f) maxTemp = temp;
            total += temp;
            Avg = total / countNum;
            countNum++;

            if(PrintPrivilegeLevel()==0x00){
                system("cls");
                /*freopen("CONOUT$", "w", stdout);
                freopen("CONOUT$", "w", stderr);
                freopen("CONIN$", "r", stdin);*/
            }

            string timeStr = UseSysTime ? GetSystemTime() : GetElapsedTime();
            if (Tlog == 1) {
                cout << "CPU Temp: " << temp << " C | Min: " << minTemp << " C | Max: " << maxTemp << " C | Avg: " << Avg << " C          \r";
                output << timeStr << " | CPU Temp: " << temp << " C | Min: " << minTemp << " C | Max: " << maxTemp << " C | Avg: " << Avg << " C" << endl;
            } else {
                if (NoDTime == 1) {
                    cout << "CPU Temp: " << temp << " C | Min: " << minTemp << " C | Max: " << maxTemp << " C | Avg: " << Avg << " C          \r";
                } else {
                    cout << "CPU Temp: " << temp << " C | Min: " << minTemp << " C | Max: " << maxTemp << " C | Avg: " << Avg << " C | Time: " << timeStr << "          \r";
                }
            }
        } else {
            cout << "Could not retrieve CPU temperature          \r";
        }
        cout.flush();
    }

    void GetTemp() {
        float minTemp = -1.0f;
        float maxTemp = -1.0f;

        while (true) {
            GetSystemInfo(minTemp, maxTemp, Tlog, UseSysTime, NoDTime);
            Sleep(400);
        }
    }
    bool FreeDllLibrary(){
        HINSTANCE hDLL = GetModuleHandleA("WinRing0x64.dll");
        if (hDLL) {
            typedef void (*DeinitializeOls)();
            DeinitializeOls deinit = (DeinitializeOls)GetProcAddress(hDLL, "DeinitializeOls");
            if (deinit) deinit();
            FreeLibrary(hDLL);
            return true;
        }
        else return false;
    }
}