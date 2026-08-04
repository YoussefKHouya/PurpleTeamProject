# Controlled Event 8 / LoadLibraryW DLL-injection validation.
# Target: temporary notepad.exe. DLL: signed Windows version.dll. No payload/persistence.
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
 [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a,bool b,int p);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint q);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint n,out IntPtr w);
 [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string n);
 [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr h,string n);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint z,IntPtr s,IntPtr p,uint f,out uint id);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
'@
$n=Start-Process notepad.exe -PassThru; Start-Sleep 1
$h=[NativeMethods]::OpenProcess(0x043A,$false,$n.Id)
if($h -eq [IntPtr]::Zero){throw 'OpenProcess failed'}
$b=[Text.Encoding]::Unicode.GetBytes("$env:WINDIR\System32\version.dll"+[char]0)
$m=[NativeMethods]::VirtualAllocEx($h,[IntPtr]::Zero,$b.Length,0x3000,0x04)
if($m -eq [IntPtr]::Zero){throw 'VirtualAllocEx failed'}
[IntPtr]$w=[IntPtr]::Zero
if(-not [NativeMethods]::WriteProcessMemory($h,$m,$b,$b.Length,[ref]$w)){throw 'WriteProcessMemory failed'}
[uint32]$tid=0
$l=[NativeMethods]::GetProcAddress([NativeMethods]::GetModuleHandle('kernel32.dll'),'LoadLibraryW')
$t=[NativeMethods]::CreateRemoteThread($h,[IntPtr]::Zero,0,$l,$m,0,[ref]$tid)
if($t -eq [IntPtr]::Zero){throw 'CreateRemoteThread failed'}
[NativeMethods]::CloseHandle($t)|Out-Null;[NativeMethods]::CloseHandle($h)|Out-Null
Stop-Process -Id $n.Id -Force
"WAZUH_PROCESS_INJECTION_PASS PID=$($n.Id) TID=$tid"
