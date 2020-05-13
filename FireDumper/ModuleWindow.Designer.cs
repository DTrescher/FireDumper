namespace FireDumper
{
    sealed partial class ModuleWindow
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ModuleWindow));
            this.moduleViewGroupBox = new System.Windows.Forms.GroupBox();
            this.ModuleList = new System.Windows.Forms.ListView();
            this.NameHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.PathHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.BaseAddressHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ModuleEntryHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ModuleSizeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ModuleTypeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ModuleListInspector = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.dumpModule = new System.Windows.Forms.ToolStripMenuItem();
            this.openInExplorer = new System.Windows.Forms.ToolStripMenuItem();
            this.moduleViewGroupBox.SuspendLayout();
            this.ModuleListInspector.SuspendLayout();
            this.SuspendLayout();
            // 
            // moduleViewGroupBox
            // 
            this.moduleViewGroupBox.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.moduleViewGroupBox.Controls.Add(this.ModuleList);
            this.moduleViewGroupBox.Location = new System.Drawing.Point(12, 12);
            this.moduleViewGroupBox.Name = "moduleViewGroupBox";
            this.moduleViewGroupBox.Size = new System.Drawing.Size(1460, 671);
            this.moduleViewGroupBox.TabIndex = 0;
            this.moduleViewGroupBox.TabStop = false;
            this.moduleViewGroupBox.Text = "Module View";
            // 
            // ModuleList
            // 
            this.ModuleList.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.ModuleList.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.NameHeader,
            this.PathHeader,
            this.BaseAddressHeader,
            this.ModuleEntryHeader,
            this.ModuleSizeHeader,
            this.ModuleTypeHeader});
            this.ModuleList.ContextMenuStrip = this.ModuleListInspector;
            this.ModuleList.FullRowSelect = true;
            this.ModuleList.HideSelection = false;
            this.ModuleList.Location = new System.Drawing.Point(6, 34);
            this.ModuleList.Name = "ModuleList";
            this.ModuleList.Size = new System.Drawing.Size(1448, 631);
            this.ModuleList.TabIndex = 0;
            this.ModuleList.UseCompatibleStateImageBehavior = false;
            this.ModuleList.View = System.Windows.Forms.View.Details;
            this.ModuleList.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ModuleList_ColumnClick);
            this.ModuleList.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.ModuleList_MouseDoubleClick);
            // 
            // NameHeader
            // 
            this.NameHeader.Text = "Name";
            this.NameHeader.Width = 240;
            // 
            // PathHeader
            // 
            this.PathHeader.Text = "Path";
            this.PathHeader.Width = 400;
            // 
            // BaseAddressHeader
            // 
            this.BaseAddressHeader.Text = "Base Address";
            this.BaseAddressHeader.Width = 200;
            // 
            // ModuleEntryHeader
            // 
            this.ModuleEntryHeader.Text = "Module Entry";
            this.ModuleEntryHeader.Width = 200;
            // 
            // ModuleSizeHeader
            // 
            this.ModuleSizeHeader.Text = "Image Size";
            this.ModuleSizeHeader.Width = 180;
            // 
            // ModuleTypeHeader
            // 
            this.ModuleTypeHeader.Text = "Image Type";
            this.ModuleTypeHeader.Width = 180;
            // 
            // ModuleListInspector
            // 
            this.ModuleListInspector.ImageScalingSize = new System.Drawing.Size(36, 36);
            this.ModuleListInspector.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.dumpModule,
            this.openInExplorer});
            this.ModuleListInspector.Name = "ModuleListInspector";
            this.ModuleListInspector.Size = new System.Drawing.Size(293, 92);
            this.ModuleListInspector.Opening += new System.ComponentModel.CancelEventHandler(this.ModuleListInspector_Opening);
            // 
            // dumpModule
            // 
            this.dumpModule.Name = "dumpModule";
            this.dumpModule.Size = new System.Drawing.Size(292, 44);
            this.dumpModule.Text = "Dump Module";
            this.dumpModule.Click += new System.EventHandler(this.dumpModule_Click);
            // 
            // openInExplorer
            // 
            this.openInExplorer.Name = "openInExplorer";
            this.openInExplorer.Size = new System.Drawing.Size(292, 44);
            this.openInExplorer.Text = "Open In Explorer";
            this.openInExplorer.Click += new System.EventHandler(this.openInExplorer_Click);
            // 
            // ModuleWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(14F, 29F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1484, 695);
            this.Controls.Add(this.moduleViewGroupBox);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.KeyPreview = true;
            this.Name = "ModuleWindow";
            this.Load += new System.EventHandler(this.ModuleWindow_Load);
            this.KeyUp += new System.Windows.Forms.KeyEventHandler(this.ModuleWindow_KeyUp);
            this.moduleViewGroupBox.ResumeLayout(false);
            this.ModuleListInspector.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox moduleViewGroupBox;
        private System.Windows.Forms.ListView ModuleList;
        private System.Windows.Forms.ColumnHeader NameHeader;
        private System.Windows.Forms.ColumnHeader PathHeader;
        private System.Windows.Forms.ColumnHeader BaseAddressHeader;
        private System.Windows.Forms.ColumnHeader ModuleEntryHeader;
        private System.Windows.Forms.ColumnHeader ModuleSizeHeader;
        private System.Windows.Forms.ColumnHeader ModuleTypeHeader;
        private System.Windows.Forms.ContextMenuStrip ModuleListInspector;
        private System.Windows.Forms.ToolStripMenuItem dumpModule;
        private System.Windows.Forms.ToolStripMenuItem openInExplorer;
    }
}