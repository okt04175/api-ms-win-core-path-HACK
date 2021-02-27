# api-ms-win-core-path-l1-1-0.dll HACK
This is a partial implementation of `api-ms-win-core-path-l1-1-0.dll` based on Wine code. It contains the functions required to run Blender 2.93 (specifically, Python 3.9) on Windows 7.

## Description

Blender 2.93 Alpha fails to start on Windows 7 because it uses Python 3.9 which requires `api-ms-win-core-path-l1-1-0.dll`.

`blender.exe` only imports `PathCchCanonicalizeEx` and `PathCchCombineEx`, so this should be sufficent for now.

## Installation
* Clone and build it yourself or download a statically precompiled [release].
* Copy the dll into Blender's installation directory.

After that it should work.

## Reference
[Windows 7 support for blender 2.93](https://blender.community/c/rightclickselect/XZgbbc/)
