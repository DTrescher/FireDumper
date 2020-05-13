using System.Runtime.InteropServices;
using System;
using System.Collections;
using System.IO;
using System.Text;
using System.Windows.Forms;

using FireDumper.Utils.PE;
using FireDumper.Utils.PE._32;
using FireDumper.Utils.PE._64;
using static FireDumper.Utils.PE.NativePEStructs;
using static FireDumper.Utils.WinAPI;

namespace FireDumper.Utils
{
    public static class Gateway
    {
        public static readonly uint IO_COPY_MEMORY_REQUEST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666 /* Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        public static readonly uint IO_READ_MEMORY_REQUEST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701 /* Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        public static readonly uint IO_WRITE_MEMORY_REQUEST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702 /* Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        public static readonly uint IO_PROCESS_LIST_REQUEST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703 /* Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        public static readonly uint IO_MODULE_LIST_REQUEST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x704 /* Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);


        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_PROCESS_LIST_REQUEST
        {
            public ulong ProcessListPtr;
            public ulong ProcessListSize;
            public ulong ProcessListCount;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_MODULE_LIST_REQUEST
        {
            public IntPtr ProcessId;
            public ulong  ModuleListPtr;
            public ulong  ModuleListSize;
            public ulong  ModuleListCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_COPY_MEMORY_REQUEST
        {
            public IntPtr ProcessId;
            public ulong  targetAddress;
            public ulong  bufferAddress;
            public ulong  bufferSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_READ_MEMORY_REQUEST
        {
            public IntPtr ProcessId;

            public IntPtr Address;
            public IntPtr Response;
            public ulong Size;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_WRITE_MEMORY_REQUEST
        {
            public IntPtr ProcessId;

            public IntPtr Address;
            public IntPtr Value;
            public ulong Size;

        }
    }

    public class Dumper
    {
        private readonly Controller c;

        public Dumper(Controller c)
        {
            this.c = c;
        }

        public bool DumpProcess(ProcessListItem processListItem, out PEFile outputFile)
        {
            IntPtr basePointer = (IntPtr)processListItem.MainModuleBase;
            IMAGE_DOS_HEADER dosHeader = ReadProcessStruct<IMAGE_DOS_HEADER>(processListItem.ProcessId, basePointer);
            outputFile = default;

            if (dosHeader.IsValid)
            {
                IntPtr peHeaderPointer = basePointer + dosHeader.e_lfanew;

                IntPtr dosStubPointer = basePointer + Marshal.SizeOf<IMAGE_DOS_HEADER>();
                byte[] dosStub = ReadProcessBytes(processListItem.ProcessId, dosStubPointer, dosHeader.e_lfanew - Marshal.SizeOf<IMAGE_DOS_HEADER>());

                var peFile = !processListItem.ImageType ? 
                    Dump64BitPE(processListItem.ProcessId, dosHeader, dosStub, peHeaderPointer) : 
                    Dump32BitPE(processListItem.ProcessId, dosHeader, dosStub, peHeaderPointer);

                if (peFile != default(PEFile))
                {
                    IntPtr sectionHeaderPointer = peHeaderPointer + peFile.GetFirstSectionHeaderOffset();

                    for (int i = 0; i < peFile.Sections.Length; i++)
                    {
                        IMAGE_SECTION_HEADER sectionHeader = ReadProcessStruct<IMAGE_SECTION_HEADER>(processListItem.ProcessId, sectionHeaderPointer);
                        peFile.Sections[i] = new PESection
                        {
                            Header = PESection.PESectionHeader.FromNativeStruct(sectionHeader),
                            InitialSize = (int)sectionHeader.VirtualSize
                        };

                        ReadSectionContent(processListItem.ProcessId, new IntPtr(basePointer.ToInt64() + sectionHeader.VirtualAddress), peFile.Sections[i]);
                        sectionHeaderPointer += Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                    }

                    //Logger.Log("Aligning Sections...");
                    peFile.AlignSectionHeaders();

                    //Logger.Log("Fixing PE Header...");
                    peFile.FixPEHeader();

                    //Logger.Log("Dump Completed !");
                    outputFile = peFile;
                    return true;
                }
            }
            return false;
        }

        public bool DumpProcess(ModuleListItem moduleListItem, IntPtr processId, out PEFile outputFile)
        {
            IntPtr basePointer = (IntPtr)moduleListItem.ModuleBase;
            IMAGE_DOS_HEADER dosHeader = ReadProcessStruct<IMAGE_DOS_HEADER>(processId, basePointer);
            outputFile = default;

            if (dosHeader.IsValid)
            {
                IntPtr peHeaderPointer = basePointer + dosHeader.e_lfanew;

                IntPtr dosStubPointer = basePointer + Marshal.SizeOf<IMAGE_DOS_HEADER>();
                byte[] dosStub = ReadProcessBytes(processId, dosStubPointer, dosHeader.e_lfanew - Marshal.SizeOf<IMAGE_DOS_HEADER>());

                var peFile = !moduleListItem.ModuleType ? 
                    Dump64BitPE(processId, dosHeader, dosStub, peHeaderPointer) : 
                    Dump32BitPE(processId, dosHeader, dosStub, peHeaderPointer);

                if (peFile != default(PEFile))
                {
                    IntPtr sectionHeaderPointer = peHeaderPointer + peFile.GetFirstSectionHeaderOffset();

                    for (int i = 0; i < peFile.Sections.Length; i++)
                    {
                        IMAGE_SECTION_HEADER sectionHeader = ReadProcessStruct<IMAGE_SECTION_HEADER>(processId, sectionHeaderPointer);
                        peFile.Sections[i] = new PESection
                        {
                            Header = PESection.PESectionHeader.FromNativeStruct(sectionHeader),
                            InitialSize = (int)sectionHeader.VirtualSize
                        };

                        ReadSectionContent(processId, new IntPtr(basePointer.ToInt64() + sectionHeader.VirtualAddress), peFile.Sections[i]);
                        sectionHeaderPointer += Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                    }

                    //Logger.Log("Aligning Sections...");
                    peFile.AlignSectionHeaders();

                    //Logger.Log("Fixing PE Header...");
                    peFile.FixPEHeader();

                    //Logger.Log("Dump Completed !");
                    outputFile = peFile;
                    return true;
                }
            }
            return false;
        }

        private PEFile Dump64BitPE(IntPtr processId, IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
        {
            IMAGE_NT_HEADERS64 peHeader = ReadProcessStruct<IMAGE_NT_HEADERS64>(processId, peHeaderPointer);

            if (peHeader.IsValid)
            {
                return new PE64File(dosHeader, peHeader, dosStub);
            }
            return default;
        }

        private PEFile Dump32BitPE(IntPtr processId, IMAGE_DOS_HEADER dosHeader, byte[] dosStub, IntPtr peHeaderPointer)
        {
            IMAGE_NT_HEADERS32 peHeader = ReadProcessStruct<IMAGE_NT_HEADERS32>(processId, peHeaderPointer);

            if (peHeader.IsValid)
            {
                return new PE32File(dosHeader, peHeader, dosStub);
            }
            return default;
        }

        private T ReadProcessStruct<T>(IntPtr processId, IntPtr address) where T : struct
        {
            IntPtr buffer = MarshalUtility.AllocEmptyStruct<T>();

            if (c.FdCopyVirtualMemory(processId, address, buffer, (ulong)Marshal.SizeOf<T>()))
            {
                return MarshalUtility.GetStructFromMemory<T>(buffer);
            }
            return default;
        }

        private bool ReadSectionContent(IntPtr processId, IntPtr sectionPointer, PESection section)
        {
            const int maxReadSize = 100;
            int readSize = section.InitialSize;

            if (sectionPointer == IntPtr.Zero || readSize == 0)
            {
                return true;
            }

            if (readSize <= maxReadSize)
            {
                section.DataSize = readSize;
                section.Content = ReadProcessBytes(processId, sectionPointer, readSize);

                return true;
            }
            else
            {
                CalculateRealSectionSize(processId, sectionPointer, section);

                if (section.DataSize != 0)
                {
                    section.Content = ReadProcessBytes(processId, sectionPointer, section.DataSize);
                    return true;
                }
            }
            return false;
        }

        private byte[] ReadProcessBytes(IntPtr processId, IntPtr address, int size)
        {
            IntPtr unmanagedBytePointer = MarshalUtility.AllocZeroFilled(size);
            c.FdCopyVirtualMemory(processId, address, unmanagedBytePointer, (ulong)size);

            byte[] buffer = new byte[size];
            Marshal.Copy(unmanagedBytePointer, buffer, 0, size);
            Marshal.FreeHGlobal(unmanagedBytePointer);

            return buffer;
        }

        private void CalculateRealSectionSize(IntPtr processId, IntPtr sectionPointer, PESection section)
        {
            const int maxReadSize = 100;
            int readSize = section.InitialSize;
            int currentReadSize = readSize % maxReadSize;

            if (currentReadSize == 0)
            {
                currentReadSize = maxReadSize;
            }
            IntPtr currentOffset = sectionPointer + readSize - currentReadSize;

            while (currentOffset.ToInt64() >= sectionPointer.ToInt64())
            {
                byte[] buffer = ReadProcessBytes(processId, currentOffset, currentReadSize);
                int codeByteCount = GetInstructionByteCount(buffer);

                if (codeByteCount != 0)
                {
                    currentOffset += codeByteCount;

                    if (sectionPointer.ToInt64() < currentOffset.ToInt64())
                    {
                        section.DataSize = (int)(currentOffset.ToInt64() - sectionPointer.ToInt64());
                        section.DataSize += 4;

                        if (section.InitialSize < section.DataSize)
                        {
                            section.DataSize = section.InitialSize;
                        }
                    }
                    break;
                }

                currentReadSize = maxReadSize;
                currentOffset -= currentReadSize;
            }
        }

        private int GetInstructionByteCount(byte[] dataBlock)
        {
            for (int i = (dataBlock.Length - 1); i >= 0; i--)
            {
                if (dataBlock[i] != 0)
                {
                    return i + 1;
                }
            }
            return 0;
        }
    }

    public class ModuleListItem
    {
        public string ModuleName { get; }
        public string ModulePath { get; }
        public ulong ModuleBase { get; }
        public ulong ModuleEntry { get; }
        public uint ModuleSize { get; }
        public bool ModuleType { get; }

        private ModuleListItem(string modulePath, ulong moduleBase, ulong moduleEntry, uint moduleSize, bool moduleType)
        {
            ModulePath = FixFilePath(modulePath);
            ModuleName = Path.GetFileName(ModulePath);
            ModuleBase = moduleBase;
            ModuleEntry = moduleEntry;
            ModuleSize = moduleSize;
            ModuleType = moduleType;
        }

        private string FixFilePath(string fileName)
        {
            if (fileName.StartsWith(@"\"))
            {
                return fileName;
            }

            StringBuilder sb = new StringBuilder(256);
            int length = WinAPI.GetLongPathName(fileName, sb, sb.Capacity);

            if (length > sb.Capacity)
            {
                sb.Capacity = length;
                length = WinAPI.GetLongPathName(fileName, sb, sb.Capacity);
            }
            return sb.ToString();
        }

        public static ModuleListItem FromByteStream(BinaryReader reader)
        {
            return new ModuleListItem
            (
                Encoding.Unicode.GetString(reader.ReadBytes(512)).Split('\0')[0],
                reader.ReadUInt64(),
                reader.ReadUInt64(),
                reader.ReadUInt32(),
                reader.ReadBoolean()
            );
        }
    }

    public class ProcessListItem
    {
        public IntPtr ProcessId { get; }
        public string ProcessName { get; }
        public string ProcessFilePath { get; }
        public ulong MainModuleBase { get; }
        public ulong MainModuleEntry { get; }
        public uint ImageSize { get; }
        public bool ImageType { get; }

        private ProcessListItem(IntPtr processId, string processFilePath, ulong mainModuleBase, ulong mainModuleEntry, uint imageSize, bool imageType)
        {
            ProcessId = processId;
            ProcessFilePath = FixFilePath(processFilePath);
            ProcessName = Path.GetFileName(ProcessFilePath);
            MainModuleBase = mainModuleBase;
            MainModuleEntry = mainModuleEntry;
            ImageSize = imageSize;
            ImageType = imageType;
        }

        private string FixFilePath(string fileName)
        {
            if (fileName.StartsWith(@"\"))
            {
                return fileName;
            }

            StringBuilder sb = new StringBuilder(256);
            int length = WinAPI.GetLongPathName(fileName, sb, sb.Capacity);

            if (length > sb.Capacity)
            {
                sb.Capacity = length;
                length = WinAPI.GetLongPathName(fileName, sb, sb.Capacity);
            }
            return sb.ToString();
        }

        public static ProcessListItem FromByteStream(BinaryReader reader)
        {
            return new ProcessListItem
            (
                new IntPtr(reader.ReadInt64()), 
                Encoding.Unicode.GetString(reader.ReadBytes(512)).Split('\0')[0],
                reader.ReadUInt64(),
                reader.ReadUInt64(),
                reader.ReadUInt32(),
                reader.ReadBoolean()
            );
        }
    }

    public class ProcessListItemComparer : IComparer
    {
        private readonly int col;
        private readonly SortOrder sortOrder;

        public ProcessListItemComparer(int column, SortOrder sortOrder)
        {
            col = column;
            this.sortOrder = sortOrder;
        }
        public int Compare(object x, object y)
        {
            ProcessListItem p1 = ((ListViewItem)x)?.Tag as ProcessListItem;
            ProcessListItem p2 = ((ListViewItem)y)?.Tag as ProcessListItem;

            if (!(p1 == null || p2 == null))
            {
                int result;
                switch (col)
                {
                    case 0:
                        result = p1.ProcessId.ToInt32().CompareTo(p2.ProcessId.ToInt32());
                        break;
                    case 1:
                        result = string.Compare(p1.ProcessName, p2.ProcessName, StringComparison.Ordinal);
                        break;
                    case 2:
                        result = string.Compare(p1.ProcessFilePath, p2.ProcessFilePath, StringComparison.Ordinal);
                        break;
                    case 3:
                        result = p1.MainModuleBase.CompareTo(p2.MainModuleBase);
                        break;
                    case 4:
                        result = p1.ImageSize.CompareTo(p2.ImageSize);
                        break;
                    case 5:
                        result = p1.ImageType.CompareTo(p2.ImageType);
                        break;
                    default:
                        result = string.CompareOrdinal(((ListViewItem) x).SubItems[col].Text, ((ListViewItem) y)?.SubItems[col].Text);
                        break;

                }

                if (sortOrder == SortOrder.Descending)
                {
                    result = -result;
                }
                return result;
            }

            return 0;
        }
    }

    public class ModuleListItemComparer : IComparer
    {
        private readonly int col;
        private readonly SortOrder sortOrder;

        public ModuleListItemComparer(int column, SortOrder sortOrder)
        {
            col = column;
            this.sortOrder = sortOrder;
        }
        public int Compare(object x, object y)
        {
            ModuleListItem p1 = ((ListViewItem)x)?.Tag as ModuleListItem;
            ModuleListItem p2 = ((ListViewItem)y)?.Tag as ModuleListItem;

            if (!(p1 == null || p2 == null))
            {
                int result;
                switch (col)
                {
                    case 0:
                        result = string.Compare(p1.ModuleName, p2.ModuleName, StringComparison.Ordinal);
                        break;
                    case 1:
                        result = string.Compare(p1.ModulePath, p2.ModulePath, StringComparison.Ordinal);
                        break;
                    case 2:
                        result = p1.ModuleBase.CompareTo(p2.ModuleBase);
                        break;
                    case 3:
                        result = p1.ModuleEntry.CompareTo(p2.ModuleEntry);
                        break;
                    case 4:
                        result = p1.ModuleSize.CompareTo(p2.ModuleSize);
                        break;
                    case 5:
                        result = p1.ModuleType.CompareTo(p2.ModuleType);
                        break;
                    default:
                        result = string.CompareOrdinal(((ListViewItem)x).SubItems[col].Text, ((ListViewItem)y)?.SubItems[col].Text);
                        break;

                }

                if (sortOrder == SortOrder.Descending)
                {
                    result = -result;
                }
                return result;
            }

            return 0;
        }
    }

    internal static class ListViewExtensions
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct LVCOLUMN
        {
            public Int32 mask;
            public Int32 cx;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pszText;
            public IntPtr hbm;
            public Int32 cchTextMax;
            public Int32 fmt;
            public Int32 iSubItem;
            public Int32 iImage;
            public Int32 iOrder;
        }

        const Int32 HDI_WIDTH = 0x0001;
        const Int32 HDI_HEIGHT = HDI_WIDTH;
        const Int32 HDI_TEXT = 0x0002;
        const Int32 HDI_FORMAT = 0x0004;
        const Int32 HDI_LPARAM = 0x0008;
        const Int32 HDI_BITMAP = 0x0010;
        const Int32 HDI_IMAGE = 0x0020;
        const Int32 HDI_DI_SETITEM = 0x0040;
        const Int32 HDI_ORDER = 0x0080;
        const Int32 HDI_FILTER = 0x0100;

        const Int32 HDF_LEFT = 0x0000;
        const Int32 HDF_RIGHT = 0x0001;
        const Int32 HDF_CENTER = 0x0002;
        const Int32 HDF_JUSTIFYMASK = 0x0003;
        const Int32 HDF_RTLREADING = 0x0004;
        const Int32 HDF_OWNERDRAW = 0x8000;
        const Int32 HDF_STRING = 0x4000;
        const Int32 HDF_BITMAP = 0x2000;
        const Int32 HDF_BITMAP_ON_RIGHT = 0x1000;
        const Int32 HDF_IMAGE = 0x0800;
        const Int32 HDF_SORTUP = 0x0400;
        const Int32 HDF_SORTDOWN = 0x0200;

        const Int32 LVM_FIRST = 0x1000;         // List messages
        const Int32 LVM_GETHEADER = LVM_FIRST + 31;
        const Int32 HDM_FIRST = 0x1200;         // Header messages
        const Int32 HDM_SETIMAGELIST = HDM_FIRST + 8;
        const Int32 HDM_GETIMAGELIST = HDM_FIRST + 9;
        const Int32 HDM_GETITEM = HDM_FIRST + 11;
        const Int32 HDM_SETITEM = HDM_FIRST + 12;

        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", EntryPoint = "SendMessage")]
        private static extern IntPtr SendMessageLVCOLUMN(IntPtr hWnd, Int32 Msg, IntPtr wParam, ref LVCOLUMN lPLVCOLUMN);


        //This method used to set arrow icon
        public static void SetSortIcon(this ListView listView, int columnIndex, SortOrder order)
        {
            IntPtr columnHeader = SendMessage(listView.Handle, LVM_GETHEADER, IntPtr.Zero, IntPtr.Zero);

            for (int columnNumber = 0; columnNumber <= listView.Columns.Count - 1; columnNumber++)
            {
                IntPtr columnPtr = new IntPtr(columnNumber);
                LVCOLUMN lvColumn = new LVCOLUMN {mask = HDI_FORMAT};

                SendMessageLVCOLUMN(columnHeader, HDM_GETITEM, columnPtr, ref lvColumn);

                if (order != SortOrder.None && columnNumber == columnIndex)
                {
                    switch (order)
                    {
                        case System.Windows.Forms.SortOrder.Ascending:
                            lvColumn.fmt &= ~HDF_SORTDOWN;
                            lvColumn.fmt |= HDF_SORTUP;
                            break;
                        case System.Windows.Forms.SortOrder.Descending:
                            lvColumn.fmt &= ~HDF_SORTUP;
                            lvColumn.fmt |= HDF_SORTDOWN;
                            break;
                    }
                    lvColumn.fmt |= (HDF_LEFT | HDF_BITMAP_ON_RIGHT);
                }
                else
                {
                    lvColumn.fmt &= ~HDF_SORTDOWN & ~HDF_SORTUP & ~HDF_BITMAP_ON_RIGHT;
                }

                SendMessageLVCOLUMN(columnHeader, HDM_SETITEM, columnPtr, ref lvColumn);
            }
        }
    }
}
