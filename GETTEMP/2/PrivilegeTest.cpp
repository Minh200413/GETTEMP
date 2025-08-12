#include <windows.h>
#include <sddl.h>
#include <iostream>

// Kiểm tra membership well-known SID
bool IsCurrentTokenInGroup(WELL_KNOWN_SID_TYPE sidType)
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        std::cerr << "Lỗi: Không thể mở token của process. Mã lỗi: " << GetLastError() << std::endl;
        return false;
    }

    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sidBuffer);
    BOOL isMember = FALSE;

    if (CreateWellKnownSid(sidType, nullptr, sidBuffer, &sidSize))
    {
        if (!CheckTokenMembership(hToken, sidBuffer, &isMember))
        {
            std::cerr << "Lỗi: Không thể kiểm tra membership. Mã lỗi: " << GetLastError() << std::endl;
        }
    }
    else
    {
        std::cerr << "Lỗi: Không thể tạo well-known SID. Mã lỗi: " << GetLastError() << std::endl;
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
        std::cerr << "Lỗi: Không thể mở token của process. Mã lỗi: " << GetLastError() << std::endl;
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
        std::cerr << "Lỗi: Không thể lấy thông tin token. Mã lỗi: " << GetLastError() << std::endl;
    }
    CloseHandle(hToken);
    return elevated;
}
bool IsCurrentTokenSystem() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "Lỗi OpenProcessToken: " << GetLastError() << std::endl;
        return false;
    }

    BYTE userSid[SECURITY_MAX_SID_SIZE];
    DWORD userSidSize = sizeof(userSid);
    TOKEN_USER* pTokenUser = (TOKEN_USER*)userSid;
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, userSidSize, &userSidSize)) {
        std::cerr << "Lỗi GetTokenInformation: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    BYTE systemSid[SECURITY_MAX_SID_SIZE];
    DWORD systemSidSize = sizeof(systemSid);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSidSize)) {
        std::cerr << "Lỗi CreateWellKnownSid: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    bool isSystem = EqualSid(pTokenUser->User.Sid, systemSid);
    CloseHandle(hToken);
    return isSystem;
}
// In ra thông báo quyền với std::cout
void PrintPrivilegeLevel()
{
    if (IsCurrentTokenSystem())
    {
        std::cout << "Quyền: SYSTEM (Local System)" << std::endl;
    }
    else if (IsProcessElevated())
    {
        std::cout << "Quyền: Administrator (elevated)" << std::endl;
    }
    else if (IsCurrentTokenInGroup(WinAccountGuestSid))
    {
        std::cout << "Quyền: Guest" << std::endl;
    }
    else
    {
        // Mọi trường hợp còn lại coi là Standard User
        std::cout << "Quyền: Standard User" << std::endl;
    }
}

int main()
{
    std::cout<<"---------------------------------------------------------";
    PrintPrivilegeLevel();
    std::cout<<"---------------------------------------------------------";
    
    return 0;
}