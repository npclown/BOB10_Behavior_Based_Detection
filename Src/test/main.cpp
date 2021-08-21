#include <Windows.h>
#include <stdio.h>
#include <fstream>
#include <string>

void DebugLog(const char* format, ...)
{
    va_list vl;
    char szLog[512] = { 0, };

    va_start(vl, format);
    wvsprintfA(szLog, format, vl);
    va_end(vl);

    OutputDebugStringA(szLog);
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("\n Usage  : test.exe <filename>\n\n");
        return -1;
    }

    std::ifstream openFile(argv[1]);

    if (openFile.is_open()) {
        std::string line;
        while (std::getline(openFile, line)) {
            DebugLog("%s",line.data());
        }
        openFile.close();
    }
}