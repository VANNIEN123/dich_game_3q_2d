@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
cl.exe /EHsc /LD /O2 "c:\Users\OS\.gemini\antigravity-ide\scratch\translator.cpp" /Fe"c:\Users\OS\.gemini\antigravity-ide\scratch\translator.dll" /Fo"c:\Users\OS\.gemini\antigravity-ide\scratch\translator.obj" gdi32.lib user32.lib ws2_32.lib
