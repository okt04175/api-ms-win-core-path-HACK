# api-ms-win-core-path-l1-1-0.dll
This is an implementation of `api-ms-win-core-path-l1-1-0.dll` based on Wine code. It is made to run Blender 2.93 (specifically, Python 3.9) on Windows 7.

## Description

For Blender 3.0 and above, see https://github.com/nalexandru/BlenderCompat

Blender 2.93 fails to start on Windows 7 because it uses Python 3.9 which requires `api-ms-win-core-path-l1-1-0.dll`.

![Blender 2.93 Alpha on Windows 7](https://raw.githubusercontent.com/nalexandru/api-ms-win-core-path-HACK/master/293_win7.png)

## Blender 2.93 installation on Windows 7

The official installer will refuse to install on Windows 7.

You can download the Portable Zip or if you prefer the installer you can download a modified version that lowers the requirement from [modified installer download](https://1drv.ms/u/s%21AhpnXywMA4U1mQHBW0R_xWClYKBP?e=YgUSLj), or you can modify the .MSI file ([instructions on how to modify the MSI](http://david-merritt.blogspot.com/2012/08/force-blocked-software-to-install-onto.html)).

## Installation
* Clone and build it yourself or download a precompiled release.
* Copy the x64 dll into Blender's installation directory or copy the x86 dll into C:\Windows\SysWOW64 and the x64 dll into C:\Windows\System32.

After that it should work.

## Reference
* [Windows 7 support for blender 2.93](https://blender.community/c/rightclickselect/XZgbbc)
* [Wine source code](https://source.winehq.org/git/wine.git/blob_plain/HEAD:/dlls/kernelbase/path.c)
* [Original project this is based on](https://github.com/kobilutil/api-ms-win-core-path-HACK)
