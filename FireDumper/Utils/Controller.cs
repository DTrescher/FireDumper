using System.Runtime.InteropServices;
using System.IO;
using System;
using System.Windows.Forms;
using static FireDumper.Utils.Gateway;
using static FireDumper.Utils.WinAPI;

namespace FireDumper.Utils
{
    public class Controller
    {
        private readonly IntPtr hDriver;

        public Controller(string registryPath)
        {
            hDriver = CreateFileA(registryPath, FileAccess.ReadWrite, FileShare.ReadWrite,
                IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
        }

        public bool HasValidHandle()
        {
            return hDriver != INVALID_HANDLE_VALUE;
        }

        public bool FdCopyVirtualMemory(IntPtr pid, IntPtr address, IntPtr buffer, ulong bufferSize)
        {
            if (hDriver != INVALID_HANDLE_VALUE)
            {
                KERNEL_COPY_MEMORY_REQUEST kcmr = new KERNEL_COPY_MEMORY_REQUEST
                {
                    ProcessId = pid,
                    targetAddress = (ulong)address.ToInt64(),
                    bufferAddress = (ulong)buffer.ToInt64(),
                    bufferSize = bufferSize
                };

                IntPtr kcmrPointer = MarshalUtility.CopyStructToMemory(kcmr);
                int krmrSize = Marshal.SizeOf<KERNEL_COPY_MEMORY_REQUEST>();

                bool result = DeviceIoControl(hDriver, IO_COPY_MEMORY_REQUEST, kcmrPointer, krmrSize, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
                Marshal.FreeHGlobal(kcmrPointer);

                return result;
            }
            return false;
        }

        public T FdReadProcessMemory<T>(IntPtr pid, IntPtr address, ulong size)
        {
            KERNEL_READ_MEMORY_REQUEST krmr = new KERNEL_READ_MEMORY_REQUEST
            {
                ProcessId = pid,
                Address = address,
                Size = size
            };

            IntPtr krmrPointer = MarshalUtility.CopyStructToMemory(krmr);
            int krmrSize = Marshal.SizeOf<KERNEL_READ_MEMORY_REQUEST>();

            if (DeviceIoControl(hDriver, IO_READ_MEMORY_REQUEST, krmrPointer, krmrSize, krmrPointer, krmrSize, IntPtr.Zero, IntPtr.Zero))
            {
                try
                {
                    krmr = MarshalUtility.GetStructFromMemory<KERNEL_READ_MEMORY_REQUEST>(krmrPointer);

                    return (T)Convert.ChangeType((ulong)krmr.Response.ToInt64(), typeof(T));
                }
                catch (Exception)
                {
                    Console.WriteLine(@"Exception in NµReadProcessMemory!");
                    return (T)Convert.ChangeType(false, typeof(T));
                }
            }

            return (T)Convert.ChangeType(false, typeof(T));
        }

        public bool FdWriteProcessMemory(IntPtr pid, IntPtr address, IntPtr value, ulong size)
        {
            KERNEL_WRITE_MEMORY_REQUEST kwmr = new KERNEL_WRITE_MEMORY_REQUEST
            {
                ProcessId = pid,
                Address = address,
                Value = value,
                Size = size
            };

            IntPtr kwmrPointer = MarshalUtility.CopyStructToMemory(kwmr);
            int kwmrSize = Marshal.SizeOf<KERNEL_WRITE_MEMORY_REQUEST>();

            return DeviceIoControl(hDriver, IO_WRITE_MEMORY_REQUEST, kwmrPointer, kwmrSize, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
        }

        private ulong FdGetProcessListSize()
        {
            IntPtr operationPointer = MarshalUtility.AllocEmptyStruct<KERNEL_PROCESS_LIST_REQUEST>();
            int operationSize = Marshal.SizeOf<KERNEL_PROCESS_LIST_REQUEST>();

            if (DeviceIoControl(hDriver, IO_PROCESS_LIST_REQUEST, operationPointer, operationSize, operationPointer, operationSize, IntPtr.Zero, IntPtr.Zero))
            {
                KERNEL_PROCESS_LIST_REQUEST operation = MarshalUtility.GetStructFromMemory<KERNEL_PROCESS_LIST_REQUEST>(operationPointer);
                return operation.ProcessListSize;
            }

            return 0;
        }

        public bool FdGetProcessList(out ProcessListItem[] result)
        {
            result = Array.Empty<ProcessListItem>();

            ulong processListSize = FdGetProcessListSize();

            if (processListSize <= 0)
                return false;

            IntPtr processListPtr = MarshalUtility.AllocZeroFilled((int)processListSize);
            KERNEL_PROCESS_LIST_REQUEST kplr = new KERNEL_PROCESS_LIST_REQUEST
            {
                ProcessListPtr = (ulong)processListPtr.ToInt64(),
                ProcessListSize = processListSize
            };
            IntPtr kplrPointer = MarshalUtility.CopyStructToMemory(kplr);
            int klprSize = Marshal.SizeOf<KERNEL_PROCESS_LIST_REQUEST>();

            if (DeviceIoControl(hDriver, IO_PROCESS_LIST_REQUEST, kplrPointer, klprSize, kplrPointer, klprSize, IntPtr.Zero, IntPtr.Zero))
            {
                kplr = MarshalUtility.GetStructFromMemory<KERNEL_PROCESS_LIST_REQUEST>(kplrPointer);

                if (kplr.ProcessListCount > 0)
                {
                    byte[] managedBuffer = new byte[processListSize];
                    Marshal.Copy(processListPtr, managedBuffer, 0, (int)processListSize);
                    Marshal.FreeHGlobal(processListPtr);

                    result = new ProcessListItem[kplr.ProcessListCount];

                    using (BinaryReader reader = new BinaryReader(new MemoryStream(managedBuffer)))
                    {
                        for (int i = 0; i < result.Length; i++)
                        {
                            result[i] = ProcessListItem.FromByteStream(reader);
                        }
                    }
                    return true;
                }
            }

            return false;
        }

        private ulong FdGetModuleListSize(IntPtr pid)
        {
            KERNEL_MODULE_LIST_REQUEST kmlr = new KERNEL_MODULE_LIST_REQUEST
            {
                ProcessId = pid,
                
            };

            IntPtr kmlrPointer = MarshalUtility.CopyStructToMemory(kmlr);
            int kmlrSize = Marshal.SizeOf<KERNEL_MODULE_LIST_REQUEST>();

            if (DeviceIoControl(hDriver, IO_MODULE_LIST_REQUEST, kmlrPointer, kmlrSize, kmlrPointer, kmlrSize, IntPtr.Zero, IntPtr.Zero))
            {
                kmlr = MarshalUtility.GetStructFromMemory<KERNEL_MODULE_LIST_REQUEST>(kmlrPointer);
                return kmlr.ModuleListSize;
            }

            return 0;
        }

        public bool FdGetModuleList(IntPtr pid, out ModuleListItem[] result)
        {
            result = Array.Empty<ModuleListItem>();

            ulong moduleListSize = FdGetModuleListSize(pid);

            if (moduleListSize <= 0)
                return false;

            IntPtr moduleListPtr = MarshalUtility.AllocZeroFilled((int)moduleListSize);
            KERNEL_MODULE_LIST_REQUEST kmlr = new KERNEL_MODULE_LIST_REQUEST
            {
                ProcessId = pid,
                ModuleListPtr = (ulong)moduleListPtr.ToInt64(),
                ModuleListSize = moduleListSize
            };
            IntPtr kmlrPointer = MarshalUtility.CopyStructToMemory(kmlr);
            int kmlrSize = Marshal.SizeOf<KERNEL_MODULE_LIST_REQUEST>();

            if (DeviceIoControl(hDriver, IO_MODULE_LIST_REQUEST, kmlrPointer, kmlrSize, kmlrPointer, kmlrSize, IntPtr.Zero, IntPtr.Zero))
            {
                kmlr = MarshalUtility.GetStructFromMemory<KERNEL_MODULE_LIST_REQUEST>(kmlrPointer);

                if (kmlr.ModuleListCount > 0)
                {
                    byte[] managedBuffer = new byte[moduleListSize];
                    Marshal.Copy(moduleListPtr, managedBuffer, 0, (int)moduleListSize);
                    Marshal.FreeHGlobal(moduleListPtr);

                    result = new ModuleListItem[kmlr.ModuleListCount];

                    using (BinaryReader reader = new BinaryReader(new MemoryStream(managedBuffer)))
                    {
                        for (int i = 0; i < result.Length; i++)
                        {
                            result[i] = ModuleListItem.FromByteStream(reader);
                        }
                    }
                    return true;
                }
            }

            return false;
        }
    }
}
