#include "API1.h"
//#include <iostream>
//using namespace std;
//namespace fs = std::filesystem;

int main(int argc, char* argv[]) {

    //get_program_name(argv[0]);
    string PROG_NAME = argv[0];
    startTime = time(nullptr);
    wstring ProgramNameW = GetExeNameNew();


    for (int i = 1; i < argc; i++) {
        string param = argv[i];
        if (param[0] == '/') param = param.substr(1);

        if (param == "templog") {
            Tlog = true;
        } else if (param == "systime") {
            UseSysTime = true;
        } else if (param == "nodtime") {
            NoDTime = true;
        }else if (param == "install"){
            Install = true;
            Unins = false;
        } else if (param == "uninstall"){
            Unins = true;
            Install = false;
        }else if (param == "system"){
            SYSTEM = true; 
        }else {
            cout << "Usage: " << argv[0] << " [/templog] [/systime] [/nodtime] [/install][/uninstall]\n";
            return 1;
        }
    }

    if(Install){
        if(InstallProgram(PROG_NAME) == 1){
            cout<<"Install program success!";
            exit(0);
        }
        else cerr<<"Error when install program ";
    }
    if(Unins){
        if(UninstallProgram() == 1){
            cout<<"Uninstall program success!";
            exit(0);
        }
        else cerr<<"Error when uninstall program ";
    }
    if(SYSTEM){
        if(!RunSystem(ProgramNameW)){
            OutputDebugStringA("ERP\n");
            wcout<<ProgramNameW;
            exit(0);
        }
    }
    
    if(!WriteD()){
        cerr<<"Error when writing files!";
        this_thread::sleep_for(std::chrono::seconds(2)); 
        exit(0);
    }
    if(WriteC())CheckAndWriteCer();
    else OutputDebugStringA("WFE\n");
    GetTemp();
    ExitProcess();
    return 0;
}