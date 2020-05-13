using System.Runtime.InteropServices;
using System.IO;
using System;
using System.Text;

namespace FireDumper.Utils
{
    public static class WinAPI
    {
        public static readonly int FILE_DEVICE_UNKNOWN = 0x22;
        public static readonly int METHOD_BUFFERED = 0x0;
        public static readonly int FILE_SPECIAL_ACCESS = 0x0;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("user32")]
        public static extern int FindWindow(string sClassName, string sAppName);

        [DllImport("user32")]
        public static extern int GetWindowThreadProcessId(int hwnd, out int processId);

        [DllImport("user32.dll")]
        public static extern short GetAsyncKeyState(System.Windows.Forms.Keys vKey);

        [DllImport("kernel32.dll")]
        public static extern int GetLongPathName(string path, StringBuilder pszPath, int cchPath);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
            [MarshalAs(UnmanagedType.LPStr)] string filename,
            [MarshalAs(UnmanagedType.U4)] FileAccess access,
            [MarshalAs(UnmanagedType.U4)] FileShare share,
            IntPtr securityAttributes,
            [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
            [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, int nInBufferSize,
            IntPtr lpOutBuffer, int nOutBufferSize,
            IntPtr lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
            ref ulong lpInBuffer, int nInBufferSize,
            IntPtr lpOutBuffer, int nOutBufferSize,
            IntPtr lpBytesReturned, IntPtr lpOverlapped);

        public static uint CTL_CODE(int deviceType, int function, int method, int access)
        {
            return (uint)(((deviceType) << 16) | ((access) << 14) | ((function) << 2) | (method));
        }
    }
}
