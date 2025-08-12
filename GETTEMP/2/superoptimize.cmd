g++ -std=c++20 -Os -s -O3 -static -static-libgcc -static-libstdc++ -flto -fexceptions MAIN.cpp -luser32 -lkernel32 -lshell32 -ladvapi32 -lcrypt32 -lshlwapi -o GettempV6.exe
