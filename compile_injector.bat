@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
cl.exe /EHsc /O2 "c:\Users\OS\.gemini\antigravity-ide\scratch\injector.cpp" /Fe"c:\Users\OS\.gemini\antigravity-ide\scratch\injector.exe" /Fo"c:\Users\OS\.gemini\antigravity-ide\scratch\injector.obj"
copy "c:\Users\OS\.gemini\antigravity-ide\scratch\injector.exe" "d:\3Q\µç»êÓÎÏ·\injector.exe"
