using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

using FireDumper.Utils;
using FireDumper.Utils.PE;

namespace FireDumper
{
    public partial class FireDumper : Form
    {
        public static readonly Controller c = new Controller("\\\\.\\Fdd001");
        public static bool HideSystemProcesses { get; private set; } = true;
        public static bool HideSystemModules { get; private set; } = false;

        public FireDumper()
        {
            InitializeComponent();
            this.ActiveControl = info01Label;
        }

        private void FireDumper_Load(object sender, EventArgs e)
        {
            logsTextBox.AppendText("[~] Waiting for driver connection ..." + Environment.NewLine);

            if (c.HasValidHandle())
                logsTextBox.AppendText("[+] Finished!" + Environment.NewLine);

            UpdateProcessList();
        }

        private void UpdateProcessList()
        {
            if (c.HasValidHandle())
            {
                if (c.FdGetProcessList(out var processList))
                {
                    ProcessList.Items.Clear();

                    var systemRootFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
                    foreach (var processItem in processList)
                    {
                        if (HideSystemProcesses &&
                            (processItem.ProcessFilePath.ToLower().StartsWith(systemRootFolder) ||
                             processItem.ProcessFilePath.StartsWith(@"\")))
                        {
                            continue;
                        }

                        if (processItem.ProcessName == "" || processItem.ProcessFilePath == "")
                        {
                            continue;
                        }

                        ListViewItem item = new ListViewItem(processItem.ProcessId.ToString());
                        item.SubItems.Add(processItem.ProcessName);
                        item.SubItems.Add(processItem.ProcessFilePath);
                        item.SubItems.Add($"0x{processItem.MainModuleBase:x8}");
                        item.SubItems.Add(processItem.ImageSize.ToString("x4"));
                        item.SubItems.Add(processItem.ImageType ? "x86" : "x64");
                        item.Tag = processItem;

                        ProcessList.Items.Add(item);
                    }
                    ProcessList.ListViewItemSorter = new ProcessListItemComparer(0, SortOrder.Ascending);
                    //logsTextBox.AppendText(@"[*] Reloading Process List... Finished!" + Environment.NewLine);
                }
            }
        }

        private void FireDumper_KeyUp(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.F5 || (e.Control && e.KeyCode == Keys.R))
            {
                UpdateProcessList();
            }

            if (e.KeyCode == Keys.F1)
            {
                HideSystemProcesses = !HideSystemProcesses;
                info02Label.Text = HideSystemProcesses ? @"Switch Mode: F1 {OFF}" : @"Switch Mode: F1 {ON}";
                UpdateProcessList();
            }

            //TODO: Add an search option
            //MessageBox.Show(@"Key: " + e.KeyCode.ToString());
            //ListViewItem foundItem = ProcessList.FindItemWithText(e.KeyCode.ToString(), true, 1, true);
            //ProcessList.Items[foundItem.Index].Selected = true;
            //ProcessList.Select();
        }

        public static ProcessListItem moduleWindowTargetProcess;
        private void ProcessList_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            moduleWindowTargetProcess = ProcessList.SelectedItems[0].Tag as ProcessListItem;
            ModuleWindow mw = new ModuleWindow() {StartPosition = FormStartPosition.CenterParent};
            mw.ShowDialog();
        }

        private static SortOrder sorting = SortOrder.Descending;
        private void ProcessList_ColumnClick(object sender, ColumnClickEventArgs e)
        {
            sorting = sorting == SortOrder.Ascending ? SortOrder.Descending : SortOrder.Ascending;

            ProcessList.ListViewItemSorter = new ProcessListItemComparer(e.Column, sorting);
            if (e.Column == 1 || e.Column == 2)
            {
                ProcessList.SetSortIcon(e.Column, sorting);
            }
        }

        private void ProcessListInspector_Opening(object sender, CancelEventArgs e)
        {
            e.Cancel = ProcessList.SelectedItems.Count == 0;
        }

        private void openInExplorer_Click(object sender, EventArgs e)
        {
            logsTextBox.AppendText(@"[*] Opening File in explorer..." + Environment.NewLine);
            if (ProcessList.SelectedItems[0].Tag is ProcessListItem targetProcess) Process.Start("explorer.exe", Path.GetDirectoryName(targetProcess.ProcessFilePath));
        }

        private void openDllSelector_Click(object sender, EventArgs e)
        {
            moduleWindowTargetProcess = ProcessList.SelectedItems[0].Tag as ProcessListItem;
            ModuleWindow mw = new ModuleWindow() { StartPosition = FormStartPosition.CenterParent };
            mw.ShowDialog();
        }

        private void dumpMainModule_Click(object sender, EventArgs e)
        {
            logsTextBox.AppendText(@"[*] Dumping main module..." + Environment.NewLine);
            if (c.HasValidHandle())
            {
                ProcessListItem targetProcess = ProcessList.SelectedItems[0].Tag as ProcessListItem;

                if (targetProcess == null)
                    return;

                Task.Run(() =>
                {

                    if (new Dumper(c).DumpProcess(targetProcess, out PEFile peFile))
                    {
                        Invoke(new Action(() =>
                        {
                            using (SaveFileDialog sfd = new SaveFileDialog())
                            {
                                sfd.FileName = targetProcess.ProcessName.Replace(".exe", "_dump.exe");
                                sfd.Filter = @"Executable File (.exe)|*.exe";

                                if (sfd.ShowDialog() == DialogResult.OK)
                                {
                                    peFile.SaveToDisk(sfd.FileName);
                                    logsTextBox.AppendText(@"[+] Saved dump to disk!" + Environment.NewLine);
                                    logsTextBox.AppendText(@"[+] Successfully dumped " + targetProcess.ProcessName + "!" + Environment.NewLine);
                                }
                                else
                                    logsTextBox.AppendText(@"[!] Dumping aborted!" + Environment.NewLine);
                            }
                        }));
                    }
                    else
                    {
                        Invoke(new Action(() =>
                        {
                            logsTextBox.AppendText(@"[-] Unknown error with Dumper!" + Environment.NewLine);
                            MessageBox.Show(@"Unable to dump target process !", @"Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }));
                    }
                });
            }
            else
            {
                //MessageBox.Show("Unable to communicate with driver ! Make sure it is loaded.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void logsTextBox_TextChanged(object sender, EventArgs e)
        {
            logsTextBox.SelectionStart = logsTextBox.Text.Length;
            logsTextBox.ScrollToCaret();
        }

        private void logsTextBox_Enter(object sender, EventArgs e)
        {
            ActiveControl = info01Label;
        }
    }
}
