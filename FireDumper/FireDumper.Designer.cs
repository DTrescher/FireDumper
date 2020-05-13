namespace FireDumper
{
    partial class FireDumper
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(FireDumper));
            this.processListGroup = new System.Windows.Forms.GroupBox();
            this.ProcessList = new System.Windows.Forms.ListView();
            this.PidHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.NameHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.PathHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.BaseAddressHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ImageSizeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ImageTypeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ProcessListInspector = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.dumpMainModule = new System.Windows.Forms.ToolStripMenuItem();
            this.openDllSelector = new System.Windows.Forms.ToolStripMenuItem();
            this.openInExplorer = new System.Windows.Forms.ToolStripMenuItem();
            this.logsGroup = new System.Windows.Forms.GroupBox();
            this.info02Label = new System.Windows.Forms.Label();
            this.info01Label = new System.Windows.Forms.Label();
            logsTextBox = new System.Windows.Forms.TextBox();
            this.processListGroup.SuspendLayout();
            this.ProcessListInspector.SuspendLayout();
            this.logsGroup.SuspendLayout();
            this.SuspendLayout();
            // 
            // processListGroup
            // 
            this.processListGroup.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.processListGroup.Controls.Add(this.ProcessList);
            this.processListGroup.Location = new System.Drawing.Point(12, 12);
            this.processListGroup.Name = "processListGroup";
            this.processListGroup.Size = new System.Drawing.Size(1777, 754);
            this.processListGroup.TabIndex = 0;
            this.processListGroup.TabStop = false;
            this.processListGroup.Text = "Process List";
            // 
            // ProcessList
            // 
            this.ProcessList.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.ProcessList.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.PidHeader,
            this.NameHeader,
            this.PathHeader,
            this.BaseAddressHeader,
            this.ImageSizeHeader,
            this.ImageTypeHeader});
            this.ProcessList.ContextMenuStrip = this.ProcessListInspector;
            this.ProcessList.FullRowSelect = true;
            this.ProcessList.HideSelection = false;
            this.ProcessList.Location = new System.Drawing.Point(6, 34);
            this.ProcessList.Name = "ProcessList";
            this.ProcessList.Size = new System.Drawing.Size(1765, 714);
            this.ProcessList.TabIndex = 0;
            this.ProcessList.UseCompatibleStateImageBehavior = false;
            this.ProcessList.View = System.Windows.Forms.View.Details;
            this.ProcessList.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ProcessList_ColumnClick);
            this.ProcessList.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.ProcessList_MouseDoubleClick);
            // 
            // PidHeader
            // 
            this.PidHeader.Text = "PID";
            this.PidHeader.Width = 100;
            // 
            // NameHeader
            // 
            this.NameHeader.Text = "Name";
            this.NameHeader.Width = 310;
            // 
            // PathHeader
            // 
            this.PathHeader.Text = "Path";
            this.PathHeader.Width = 585;
            // 
            // BaseAddressHeader
            // 
            this.BaseAddressHeader.Text = "Base Address";
            this.BaseAddressHeader.Width = 206;
            // 
            // ImageSizeHeader
            // 
            this.ImageSizeHeader.Text = "Image Size";
            this.ImageSizeHeader.Width = 200;
            // 
            // ImageTypeHeader
            // 
            this.ImageTypeHeader.Text = "Image Type";
            this.ImageTypeHeader.Width = 180;
            // 
            // ProcessListInspector
            // 
            this.ProcessListInspector.ImageScalingSize = new System.Drawing.Size(36, 36);
            this.ProcessListInspector.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.dumpMainModule,
            this.openDllSelector,
            this.openInExplorer});
            this.ProcessListInspector.Name = "ProcessListInspector";
            this.ProcessListInspector.Size = new System.Drawing.Size(334, 136);
            this.ProcessListInspector.Opening += new System.ComponentModel.CancelEventHandler(this.ProcessListInspector_Opening);
            // 
            // dumpMainModule
            // 
            this.dumpMainModule.Name = "dumpMainModule";
            this.dumpMainModule.Size = new System.Drawing.Size(333, 44);
            this.dumpMainModule.Text = "Dump Main Module";
            this.dumpMainModule.Click += new System.EventHandler(this.dumpMainModule_Click);
            // 
            // openDllSelector
            // 
            this.openDllSelector.Name = "openDllSelector";
            this.openDllSelector.Size = new System.Drawing.Size(333, 44);
            this.openDllSelector.Text = "Open Dll SubView";
            this.openDllSelector.Click += new System.EventHandler(this.openDllSelector_Click);
            // 
            // openInExplorer
            // 
            this.openInExplorer.Name = "openInExplorer";
            this.openInExplorer.Size = new System.Drawing.Size(333, 44);
            this.openInExplorer.Text = "Open In Explorer";
            this.openInExplorer.Click += new System.EventHandler(this.openInExplorer_Click);
            // 
            // logsGroup
            // 
            this.logsGroup.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.logsGroup.Controls.Add(this.info02Label);
            this.logsGroup.Controls.Add(this.info01Label);
            this.logsGroup.Controls.Add(logsTextBox);
            this.logsGroup.Font = new System.Drawing.Font("Microsoft Sans Serif", 8F);
            this.logsGroup.Location = new System.Drawing.Point(12, 773);
            this.logsGroup.Name = "logsGroup";
            this.logsGroup.Size = new System.Drawing.Size(1777, 217);
            this.logsGroup.TabIndex = 1;
            this.logsGroup.TabStop = false;
            this.logsGroup.Text = "Logs";
            // 
            // info02Label
            // 
            this.info02Label.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.info02Label.AutoSize = true;
            this.info02Label.Location = new System.Drawing.Point(1293, 170);
            this.info02Label.Name = "info02Label";
            this.info02Label.Size = new System.Drawing.Size(265, 29);
            this.info02Label.TabIndex = 2;
            this.info02Label.Text = "Switch Mode: F1 {OFF}";
            // 
            // info01Label
            // 
            this.info01Label.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.info01Label.AutoSize = true;
            this.info01Label.Font = new System.Drawing.Font("Microsoft Sans Serif", 8F);
            this.info01Label.Location = new System.Drawing.Point(1576, 170);
            this.info01Label.Name = "info01Label";
            this.info01Label.Size = new System.Drawing.Size(137, 29);
            this.info01Label.TabIndex = 0;
            this.info01Label.Text = "Refresh: F5";
            // 
            // logsTextBox
            // 
            logsTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
                                                                                   | System.Windows.Forms.AnchorStyles.Left) 
                                                                                  | System.Windows.Forms.AnchorStyles.Right)));
            logsTextBox.BackColor = System.Drawing.SystemColors.Control;
            logsTextBox.Font = new System.Drawing.Font("Consolas", 8F);
            logsTextBox.Location = new System.Drawing.Point(6, 34);
            logsTextBox.Multiline = true;
            logsTextBox.Name = "logsTextBox";
            logsTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            logsTextBox.Size = new System.Drawing.Size(1765, 177);
            logsTextBox.TabIndex = 1;
            logsTextBox.TextChanged += new System.EventHandler(this.logsTextBox_TextChanged);
            logsTextBox.Enter += new System.EventHandler(this.logsTextBox_Enter);
            // 
            // FireDumper
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(14F, 29F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1801, 1002);
            this.Controls.Add(this.logsGroup);
            this.Controls.Add(this.processListGroup);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.KeyPreview = true;
            this.Name = "FireDumper";
            this.Text = "FireDumper";
            this.Load += new System.EventHandler(this.FireDumper_Load);
            this.KeyUp += new System.Windows.Forms.KeyEventHandler(this.FireDumper_KeyUp);
            this.processListGroup.ResumeLayout(false);
            this.ProcessListInspector.ResumeLayout(false);
            this.logsGroup.ResumeLayout(false);
            this.logsGroup.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox processListGroup;
        private System.Windows.Forms.GroupBox logsGroup;
        private System.Windows.Forms.Label info01Label;
        private System.Windows.Forms.ListView ProcessList;
        private System.Windows.Forms.ColumnHeader PidHeader;
        private System.Windows.Forms.ColumnHeader NameHeader;
        private System.Windows.Forms.ColumnHeader PathHeader;
        private System.Windows.Forms.ColumnHeader BaseAddressHeader;
        private System.Windows.Forms.ColumnHeader ImageSizeHeader;
        private System.Windows.Forms.ColumnHeader ImageTypeHeader;
        private System.Windows.Forms.ContextMenuStrip ProcessListInspector;
        private System.Windows.Forms.ToolStripMenuItem dumpMainModule;
        private System.Windows.Forms.ToolStripMenuItem openInExplorer;
        private System.Windows.Forms.ToolStripMenuItem openDllSelector;
        private System.Windows.Forms.Label info02Label;
        public static System.Windows.Forms.TextBox logsTextBox;
    }
}

