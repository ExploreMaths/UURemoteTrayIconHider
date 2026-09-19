# Hide UU Remote (NetEase GameViewer) system-tray icon at boot - no explorer restart needed.
#
# How it works:
#   The script takes over GameViewer's autostart entry, launches the app itself,
#   then patches Shell_NotifyIconW in the target process: the IAT slot for that
#   API is redirected to a tiny stub (mov eax, 1; ret), so every call reports
#   success without ever registering a tray icon. Polling every 20 ms with a
#   pre-cached IAT map wins the race against the app's own registration, so the
#   icon never appears at all - in the taskbar or in the overflow menu.
#
# Autostart: put a shortcut of this script in the shell:startup folder with target:
#   powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "<this file>"
#
# Restore: 1) remove the startup-folder shortcut
#          2) re-enable autostart inside the UU Remote app settings (or restore the
#             backed-up value at HKCU\Software\HideUUTray\GameViewerAutostart into
#             HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GameViewer)
#          3) reboot. The patch lives only in memory; nothing persists.

$ErrorActionPreference = 'SilentlyContinue'
$logFile = Join-Path $env:TEMP 'HideUUTray.log'

function Log([string]$msg) {
    Add-Content -Path $logFile -Value ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg) -Encoding UTF8
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class P {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint a, bool b, uint c);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, UIntPtr s, uint t, uint p);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr w);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, UIntPtr s, out UIntPtr r);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtectEx(IntPtr h, IntPtr a, UIntPtr s, uint n, out uint o);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint f, uint p);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool Process32FirstW(IntPtr s, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool Process32NextW(IntPtr s, ref PROCESSENTRY32W e);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32W { public uint dwSize; public uint cntUsage; public uint th32ProcessID; public IntPtr th32DefaultHeapID; public uint th32ModuleID; public uint cntThreads; public uint th32ParentProcessID; public int pcPriClassBase; public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string szExeFile; }
    public static readonly byte[] Stub = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // mov eax,1; ret
    // 0 = failed, 1 = already patched, 2 = patched by this call
    public static int Patch(IntPtr hProc, IntPtr slotVa) {
        UIntPtr n; byte[] cur = new byte[8];
        if (!ReadProcessMemory(hProc, slotVa, cur, (UIntPtr)8, out n) || n.ToUInt64() != 8) return 0;
        IntPtr curVal = new IntPtr(BitConverter.ToInt64(cur, 0));
        byte[] probe = new byte[6];
        if (ReadProcessMemory(hProc, curVal, probe, (UIntPtr)6, out n) && n.ToUInt64() == 6) {
            bool ok = true;
            for (int i = 0; i < 6; i++) if (probe[i] != Stub[i]) { ok = false; break; }
            if (ok) return 1;
        }
        IntPtr stub = VirtualAllocEx(hProc, IntPtr.Zero, (UIntPtr)64, 0x1000, 0x40);
        if (stub == IntPtr.Zero) return 0;
        if (!WriteProcessMemory(hProc, stub, Stub, (UIntPtr)6, out n)) return 0;
        uint old;
        VirtualProtectEx(hProc, slotVa, (UIntPtr)8, 0x04, out old);
        bool w = WriteProcessMemory(hProc, slotVa, BitConverter.GetBytes(stub.ToInt64()), (UIntPtr)8, out n);
        VirtualProtectEx(hProc, slotVa, (UIntPtr)8, old, out old);
        return w ? 2 : 0;
    }
    // Fast snapshot enumeration of GameViewer.exe pids
    public static System.Collections.Generic.List<uint> FindGameViewer() {
        var list = new System.Collections.Generic.List<uint>();
        IntPtr snap = CreateToolhelp32Snapshot(0x00000002, 0); // TH32CS_SNAPPROCESS
        if (snap == new IntPtr(-1)) return list;
        PROCESSENTRY32W e = new PROCESSENTRY32W(); e.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));
        if (Process32FirstW(snap, ref e)) {
            do { if (e.szExeFile.Equals("GameViewer.exe", StringComparison.OrdinalIgnoreCase)) list.Add(e.th32ProcessID); } while (Process32NextW(snap, ref e));
        }
        CloseHandle(snap);
        return list;
    }
}
'@

# Parse a PE import table and return the IAT slot RVAs of Shell_NotifyIconW/A (cached).
$slotsCache = @{}
function Get-Slots([string]$path) {
    if ($slotsCache.ContainsKey($path)) { return $slotsCache[$path] }
    $r = @()
    try {
        $b = [IO.File]::ReadAllBytes($path)
        $u16 = { param($o) [BitConverter]::ToUInt16($b, $o) }
        $u32 = { param($o) [BitConverter]::ToUInt32($b, $o) }
        $e = [BitConverter]::ToInt32($b, 0x3C)
        $ns = & $u16 ($e + 6)
        $oo = $e + 24
        $64 = (& $u16 $oo) -eq 0x20B
        $nd = & $u32 ($oo + $(if ($64) { 108 } else { 92 }))
        $dd = $oo + $(if ($64) { 112 } else { 96 })
        $so = $dd + $nd * 8
        $secs = @()
        for ($i = 0; $i -lt $ns; $i++) {
            $o = $so + $i * 40
            $secs += @{ VA = & $u32 ($o + 12); VS = & $u32 ($o + 8); RS = & $u32 ($o + 16); RP = & $u32 ($o + 20) }
        }
        function R2O([uint32]$rva) {
            foreach ($s in $secs) { if ($rva -ge $s.VA -and $rva -lt $s.VA + [Math]::Max($s.VS, $s.RS)) { return $rva - $s.VA + $s.RP } }
            return $rva
        }
        function Asc($o) { $e2 = $o; while ($b[$e2] -ne 0) { $e2++ }; [Text.Encoding]::ASCII.GetString($b, $o, $e2 - $o) }
        $ir = & $u32 ($dd + 8)
        if ($ir -ne 0) {
            $do = R2O $ir
            $k = 0
            while ($true) {
                $oft = & $u32 ($do + $k * 20)
                $nr = & $u32 ($do + $k * 20 + 12)
                $ft = & $u32 ($do + $k * 20 + 16)
                if ($nr -eq 0 -and $ft -eq 0) { break }
                $to = R2O $(if ($oft) { $oft } else { $ft })
                $i = 0
                while ($true) {
                    $t = [BitConverter]::ToUInt64($b, $to + $i * 8)
                    if ($t -eq 0) { break }
                    if (($t -band 0x8000000000000000) -eq 0) {
                        $fn = Asc ((R2O ([uint32]($t -band 0x7FFFFFFF))) + 2)
                        if ($fn -eq 'Shell_NotifyIconW' -or $fn -eq 'Shell_NotifyIconA') { $r += [uint32]($ft + $i * 8) }
                    }
                    $i++
                }
                $k++
            }
        }
    } catch {}
    $slotsCache[$path] = $r
    return $r
}

# Patch one process; returns 0/1/2 (same as P.Patch, worst slot wins); -1 = no slots.
function Patch-Pid([uint32]$procId) {
    $proc = Get-Process -Id $procId
    if (-not $proc -or -not $proc.Path) { return 0 }
    $slots = Get-Slots $proc.Path
    if ($slots.Count -eq 0) { return -1 }
    $h = [P]::OpenProcess(0x0008 -bor 0x0010 -bor 0x0020 -bor 0x0400, $false, $procId)
    if ($h -eq [IntPtr]::Zero) { return 0 }
    try {
        $base = $proc.MainModule.BaseAddress
        $worst = 1
        foreach ($s in $slots) {
            $r = [P]::Patch($h, [IntPtr]::new($base.ToInt64() + $s))
            if ($r -eq 0) { $worst = 0 } elseif ($r -eq 2 -and $worst -eq 1) { $worst = 2 }
        }
        return $worst
    } finally { [P]::CloseHandle($h) | Out-Null }
}

# ================= Main =================
Log '===== started ====='

# 1) Take over GameViewer autostart: back up and remove its Run value; this script launches it instead.
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$backupKey = 'HKCU:\Software\HideUUTray'
$launchCmd = $null
$existing = Get-ItemProperty $runKey -Name 'GameViewer' -ErrorAction SilentlyContinue
if ($existing) {
    $launchCmd = $existing.GameViewer
    New-Item $backupKey -Force | Out-Null
    Set-ItemProperty $backupKey -Name 'GameViewerAutostart' -Value ([string]$launchCmd)
    Remove-ItemProperty $runKey -Name 'GameViewer'
    Log "autostart taken over: $launchCmd"
} else {
    $launchCmd = [string]((Get-ItemProperty $backupKey -Name 'GameViewerAutostart' -ErrorAction SilentlyContinue).GameViewerAutostart)
}

# 2) Snapshot processes already running before we launch (only on the very first switch-over).
$prePids = @([P]::FindGameViewer())

# 3) Launch UU Remote if it is not running.
if ($prePids.Count -eq 0 -and $launchCmd) {
    if ($launchCmd -match '^"([^"]+)"\s*(.*)$') { $exe = $matches[1]; $arg = $matches[2].Trim() }
    elseif ($launchCmd -match '^(\S+)\s*(.*)$') { $exe = $matches[1]; $arg = $matches[2].Trim() }
    if ($exe -and (Test-Path $exe)) {
        # Pre-cache the IAT map so the patch lands within milliseconds of process creation.
        Get-Slots $exe | Out-Null
        $inner = Join-Path (Split-Path $exe -Parent) 'bin\GameViewer.exe'
        if (Test-Path $inner) { Get-Slots $inner | Out-Null }
        if ($arg) { Start-Process $exe -ArgumentList $arg } else { Start-Process $exe }
        Log "launched UU Remote: $exe $arg"
    } else { Log "cannot parse autostart command: $launchCmd" }
}

# 4) Rapid polling: patch each GameViewer process before it can register the tray icon.
$deadline = (Get-Date).AddSeconds(120)
$startTime = Get-Date
$seenAny = $false
$needRestartExplorer = $false
$prePidSet = @{}
foreach ($pp in $prePids) { $prePidSet[$pp] = $true }

while ((Get-Date) -lt $deadline) {
    $pids = @([P]::FindGameViewer())
    if ($pids.Count -gt 0) { $seenAny = $true }
    $allDone = $true
    foreach ($procId in $pids) {
        $r = Patch-Pid $procId
        if ($r -eq 0) { $allDone = $false }
        elseif ($r -eq 2) {
            Log "patched PID=$procId"
            if ($prePidSet.ContainsKey($procId)) { $needRestartExplorer = $true }
        }
        elseif ($r -eq 1 -and $prePidSet.ContainsKey($procId)) { $prePidSet.Remove($procId) }
    }
    # Exit once a process has been seen, nothing is left to patch, and 15 s have
    # elapsed (the inner exe spawns a moment after the outer launcher).
    if ($seenAny -and $allDone -and ((Get-Date) - $startTime).TotalSeconds -gt 15) { break }
    Start-Sleep -Milliseconds 20
}

# 5) Restart explorer ONLY in the one-time switch-over case (icon already existed).
if ($needRestartExplorer) {
    Log 'icons already present; restarting explorer once to clear them (never needed again)'
    Stop-Process -Name explorer -Force
} else {
    Log 'done, explorer left untouched'
}

# 6) Safety net: keep the icon pinned to the overflow menu in case a manually
#    started instance ever gets past the patch (IsPromoted = 0).
$nbase = 'HKCU:\Control Panel\NotifyIconSettings'
if (Test-Path $nbase) {
    foreach ($key in (Get-ChildItem $nbase)) {
        $exePath = [string]$key.GetValue('ExecutablePath')
        if ($exePath -match 'gameviewer|netease[\\/]uu') {
            Set-ItemProperty -Path $key.PSPath -Name 'IsPromoted' -Value 0 -Type DWord
        }
    }
}
Log 'exited'
