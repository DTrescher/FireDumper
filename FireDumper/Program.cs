using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FireDumper
{
    static class Program
    {
        /// <summary>C:\Users\Daniel\source\repos\FireDumper\FireDumper\Program.cs
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new FireDumper());
        }
    }
}
