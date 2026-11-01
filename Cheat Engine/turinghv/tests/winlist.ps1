param([int]$ProcessId)
Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class WinList {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    public static List<string> List(uint pid) {
        var r = new List<string>();
        EnumWindows((h, l) => {
            uint p; GetWindowThreadProcessId(h, out p);
            if (p == pid && IsWindowVisible(h)) {
                var t = new StringBuilder(512); GetWindowText(h, t, 512);
                var c = new StringBuilder(256); GetClassName(h, c, 256);
                r.Add("WINDOW [" + c + "] " + t);
                EnumChildWindows(h, (ch, l2) => {
                    var ct = new StringBuilder(1024); GetWindowText(ch, ct, 1024);
                    if (ct.Length > 0) r.Add("    " + ct.ToString().Replace("\r", " ").Replace("\n", " "));
                    return true; }, IntPtr.Zero);
            }
            return true; }, IntPtr.Zero);
        return r;
    }
}
"@
[WinList]::List([uint32]$ProcessId) | Out-String
