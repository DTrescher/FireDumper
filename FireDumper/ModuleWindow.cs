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
    public sealed partial class ModuleWindow : Form
    {
        private readonly ProcessListItem targetProcess = FireDumper.moduleWindowTargetProcess;
        public ModuleWindow()
        {
            InitializeComponent();
            Text = $@"Properties of {targetProcess.ProcessName} ({targetProcess.ProcessId})";
        }

        private void ModuleWindow_Load(object sender, EventArgs e)
        {
            UpdateModuleList();
        }

        private void UpdateModuleList()
        {
            if (FireDumper.c.HasValidHandle())
            {
                if (FireDumper.c.FdGetModuleList(targetProcess.ProcessId, out var moduleList))
                {
                    ModuleList.Items.Clear();

                    var systemRootFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
                    foreach (var moduleItem in moduleList)
                    {
                        if (FireDumper.HideSystemModules &&
                            (moduleItem.ModulePath.ToLower().StartsWith(systemRootFolder) ||
                             moduleItem.ModulePath.StartsWith(@"\")))
                        {
                            continue;
                        }

                        if (moduleItem.ModuleName == "" || moduleItem.ModulePath == "")
                        {
                            continue;
                        }

                        ListViewItem item = new ListViewItem(moduleItem.ModuleName);
                        item.SubItems.Add(moduleItem.ModulePath);
                        item.SubItems.Add($"0x{moduleItem.ModuleBase:x8}");
                        item.SubItems.Add($"0x{moduleItem.ModuleEntry:x8}");
                        item.SubItems.Add(moduleItem.ModuleSize.ToString("x4"));
                        item.SubItems.Add(moduleItem.ModuleType ? "x86" : "x64");
                        item.Tag = moduleItem;

                        ModuleList.Items.Add(item);
                    }
                    ModuleList.ListViewItemSorter = new ModuleListItemComparer(0, SortOrder.Ascending);
                    //FireDumper.logsTextBox.AppendText(@"[*] Reloading Module List... Finished!" + Environment.NewLine);
                }
            }
        }

        private void DumpModule()
        {
            FireDumper.logsTextBox.AppendText(@"[*] Dumping module..." + Environment.NewLine);
            if (FireDumper.c.HasValidHandle())
            {
                ModuleListItem targetModule = ModuleList.SelectedItems[0].Tag as ModuleListItem;

                if (targetModule == null)
                {
                    FireDumper.logsTextBox.AppendText(@"[-] Dumping module aborted! (No module selected)" + Environment.NewLine);
                    return;
                }

                Task.Run(() =>
                {

                    if (new Dumper(FireDumper.c).DumpProcess(targetModule, targetProcess.ProcessId, out PEFile peFile))
                    {
                        Invoke(new Action(() =>
                        {
                            using (SaveFileDialog sfd = new SaveFileDialog())
                            {
                                string fileEnding = targetModule.ModuleName.Split('.').Last();

                                switch (fileEnding)
                                {
                                    case "dll":
                                        sfd.FileName = targetModule.ModuleName.Replace(".dll", "_dump.dll");
                                        sfd.Filter = @"Dynamic Link Library (.dll)|*.dll";
                                        break;

                                    case "exe":
                                        sfd.FileName = targetProcess.ProcessName.Replace(".exe", "_dump.exe");
                                        sfd.Filter = @"Executable File (.exe)|*.exe";
                                        break;
                                    default:
                                        sfd.FileName = targetProcess.ProcessName.Replace($".{fileEnding}", $"_dump.{fileEnding}");
                                        sfd.Filter = $@"Custom PE File (.{fileEnding})|*.{fileEnding}";
                                        break;
                                }

                                if (sfd.ShowDialog() == DialogResult.OK)
                                {
                                    peFile.SaveToDisk(sfd.FileName);
                                    FireDumper.logsTextBox.AppendText(@"[+] Saved dump to disk!" + Environment.NewLine);
                                    FireDumper.logsTextBox.AppendText(@"[+] Successfully dumped " + targetModule.ModuleName + "!" + Environment.NewLine);
                                }
                                else
                                    FireDumper.logsTextBox.AppendText(@"[!] Dumping aborted!" + Environment.NewLine);
                            }
                        }));
                    }
                    else
                    {
                        Invoke(new Action(() =>
                        {
                            FireDumper.logsTextBox.AppendText(@"[-] Unknown error with Dumper!" + Environment.NewLine);
                            MessageBox.Show(@"Unable to dump target module!", @"Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }));
                    }
                });
            }
        }

        private void ModuleWindow_KeyUp(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.F5 || (e.Control && e.KeyCode == Keys.R))
            {
                UpdateModuleList();
            }
        }

        private static SortOrder sorting = SortOrder.Descending;
        private void ModuleList_ColumnClick(object sender, ColumnClickEventArgs e)
        {
            sorting = sorting == SortOrder.Ascending ? SortOrder.Descending : SortOrder.Ascending;

            ModuleList.ListViewItemSorter = new ModuleListItemComparer(e.Column, sorting);
            if (e.Column == 0 || e.Column == 1)
            {
                ModuleList.SetSortIcon(e.Column, sorting);
            }
        }

        private void openInExplorer_Click(object sender, EventArgs e)
        {
            FireDumper.logsTextBox.AppendText(@"[*] Opening File in explorer..." + Environment.NewLine);
            if (ModuleList.SelectedItems[0].Tag is ModuleListItem targetModule) Process.Start("explorer.exe", Path.GetDirectoryName(targetModule.ModulePath));
        }

        private void dumpModule_Click(object sender, EventArgs e)
        {
            DumpModule();
        }

        private void ModuleListInspector_Opening(object sender, CancelEventArgs e)
        {
            e.Cancel = ModuleList.SelectedItems.Count == 0;
        }

        private void ModuleList_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            DumpModule();
        }
    }
}
