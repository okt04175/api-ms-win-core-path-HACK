# api-ms-win-core-path-l1-1-0.dll
This is a partial implementation of `api-ms-win-core-path-l1-1-0.dll` based on Wine code. It contains the functions required to run Blender 2.93 (specifically, Python 3.9) on Windows 7.

## Description

Blender 2.93 Alpha fails to start on Windows 7 because it uses Python 3.9 which requires `api-ms-win-core-path-l1-1-0.dll`.

`blender.exe` only imports `PathCchCanonicalizeEx` and `PathCchCombineEx`, so this should be sufficent unless there will be other changes during the 2.93 development cycle to make it incompatible with Windows 7.

![Blender 2.93 Alpha on Windows 7](https://raw.githubusercontent.com/nalexandru/api-ms-win-core-path-HACK/master/293_win7.png)

## Installation
* Clone and build it yourself or download a statically precompiled [release].
* Copy the dll into Blender's installation directory.

After that it should work.

## Reference
* [Windows 7 support for blender 2.93](https://blender.community/c/rightclickselect/XZgbbc/)
* [Wine source code](https://source.winehq.org/git/wine.git/blob_plain/HEAD:/dlls/kernelbase/path.c)
* [Original project this is based on](https://github.com/kobilutil/api-ms-win-core-path-HACK)
