// Oculyx Windows companion: a tiny setup window, a silent installer and a tray status icon in ONE exe.
// Compiled with the C# compiler that ships with Windows (C# 5 / .NET Framework 4.x), so no SDK is needed.
//
//   OculyxSetup.exe              setup window (the server stamps the server address + token into the file it serves)
//   OculyxSetup.exe --silent     unattended install (GPO / Intune / scripts), exit code 0 = ok
//   OculyxSetup.exe --uninstall  remove the agent (add --silent to skip the message boxes)
//   OculyxTray.exe               tray icon (same file, installed under that name): green = connected
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Oculyx agent setup")]
[assembly: System.Reflection.AssemblyProduct("Oculyx")]
[assembly: System.Reflection.AssemblyVersion("0.3.0.0")]

namespace Oculyx
{
    static class Theme
    {
        public static readonly Color Bg = Color.FromArgb(11, 14, 19);
        public static readonly Color Panel = Color.FromArgb(16, 20, 27);
        public static readonly Color Line = Color.FromArgb(43, 52, 68);
        public static readonly Color Text = Color.FromArgb(231, 234, 240);
        public static readonly Color Muted = Color.FromArgb(139, 149, 167);
        public static readonly Color Accent = Color.FromArgb(45, 212, 191);
        public static readonly Color AccentInk = Color.FromArgb(4, 32, 28);
        public static readonly Color Ok = Color.FromArgb(52, 211, 153);
        public static readonly Color Bad = Color.FromArgb(248, 113, 113);

        public static Font Ui(float size, FontStyle style)
        {
            return new Font("Segoe UI", size, style, GraphicsUnit.Point);
        }

        /// <summary>The Oculyx mark: a ring with a dot.</summary>
        public static Bitmap Mark(int size, Color color)
        {
            var bmp = new Bitmap(size, size);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                float s = size;
                float pen = Math.Max(2f, s * 0.12f);
                using (var p = new Pen(color, pen))
                    g.DrawEllipse(p, pen, pen, s - 2 * pen, s - 2 * pen);
                float d = s * 0.32f;
                using (var b = new SolidBrush(color))
                    g.FillEllipse(b, (s - d) / 2f, (s - d) / 2f, d, d);
            }
            return bmp;
        }
    }

    /// <summary>Settings the server stamped onto the end of this exe: [json][int32 length]["OCXCFG01"].</summary>
    sealed class Config
    {
        public string Server = "";
        public string Token = "";
        public string Name = "";
        public bool AllowActions;
        public bool Stamped { get { return Server.Length > 0 && Token.Length > 0; } }

        const string Magic = "OCXCFG01";

        static string Str(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) && v != null ? v.ToString() : "";
        }

        public static Config Read(string path)
        {
            var c = new Config();
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (fs.Length < 12) return c;
                    var tail = new byte[12];
                    fs.Seek(-12, SeekOrigin.End);
                    ReadFully(fs, tail);
                    if (Encoding.ASCII.GetString(tail, 4, 8) != Magic) return c;
                    int len = BitConverter.ToInt32(tail, 0);
                    if (len <= 0 || len > 8192 || len + 12 > fs.Length) return c;
                    var json = new byte[len];
                    fs.Seek(-(12 + len), SeekOrigin.End);
                    ReadFully(fs, json);
                    var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(json));
                    c.Server = Str(d, "server");
                    c.Token = Str(d, "token");
                    c.Name = Str(d, "name");
                    object allow;
                    c.AllowActions = d.TryGetValue("allow", out allow) && allow is bool && (bool)allow;
                }
            }
            catch (Exception) { /* not stamped, or unreadable: fall back to asking */ }
            return c;
        }

        static void ReadFully(Stream s, byte[] buf)
        {
            int off = 0;
            while (off < buf.Length)
            {
                int n = s.Read(buf, off, buf.Length - off);
                if (n <= 0) throw new EndOfStreamException();
                off += n;
            }
        }
    }

    static class Check
    {
        static readonly Regex ServerRe = new Regex(@"^https?://[A-Za-z0-9.\-_:\[\]]+(/[A-Za-z0-9.\-_/]*)?$");
        static readonly Regex TokenRe = new Regex(@"^[A-Za-z0-9_\-]{8,80}$");
        static readonly Regex NameRe = new Regex(@"^[A-Za-z0-9._ \-]{1,60}$");
        public static bool Server(string s) { return ServerRe.IsMatch(s ?? ""); }
        public static bool Token(string s) { return TokenRe.IsMatch(s ?? ""); }
        public static bool Name(string s) { return NameRe.IsMatch(s ?? ""); }
    }

    static class Native
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool DestroyIcon(IntPtr handle);
    }

    /// <summary>Runs the real install.ps1 (the same script the PowerShell one-liner uses) and streams its output.</summary>
    sealed class Installer
    {
        public bool Succeeded;
        public bool Failed;
        public string LastError = "";
        public Action<string> OnLine = delegate { };

        public static string PowerShellExe()
        {
            return Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        }

        static string Esc(string s) { return (s ?? "").Replace("'", "''"); }

        public int RunScript(string command)
        {
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
            var psi = new ProcessStartInfo(PowerShellExe(), "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var p = new Process())
            {
                p.StartInfo = psi;
                DataReceivedEventHandler handler = delegate (object s, DataReceivedEventArgs e)
                {
                    if (e.Data == null) return;
                    string line = e.Data.TrimEnd();
                    if (line.Length == 0) return;
                    if (line.StartsWith("ERROR:")) { Failed = true; LastError = line.Substring(6).Trim(); }
                    if (line.IndexOf("Connected to Oculyx", StringComparison.Ordinal) >= 0) Succeeded = true;
                    OnLine(line);
                };
                p.OutputDataReceived += handler;
                p.ErrorDataReceived += handler;
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                p.WaitForExit();
                return p.ExitCode;
            }
        }

        public int Install(Config c, bool startTray)
        {
            string cmd = "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; " +
                         "& ([scriptblock]::Create((irm '" + Esc(c.Server) + "/install.ps1'))) -Token '" + Esc(c.Token) + "' -Name '" + Esc(c.Name) + "'" +
                         (c.AllowActions ? " -AllowActions" : "") +
                         " -TrayExe '" + Esc(Application.ExecutablePath) + "'" + (startTray ? " -StartTray" : "");
            return RunScript(cmd);
        }

        public int Uninstall(string localScript, string server)
        {
            string cmd = localScript != null
                ? "& '" + Esc(localScript) + "' -Uninstall -Purge"
                : "& ([scriptblock]::Create((irm '" + Esc(server) + "/install.ps1'))) -Uninstall -Purge";
            return RunScript("[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; " + cmd);
        }
    }

    static class Program
    {
        public static bool Has(string[] args, string flag)
        {
            foreach (string a in args) if (string.Equals(a, flag, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>Relaunches this exe elevated (UAC prompt). Returns false if the user declined.</summary>
        public static bool Elevate(string arguments, string exePath)
        {
            try
            {
                Process.Start(new ProcessStartInfo(exePath) { UseShellExecute = true, Verb = "runas", Arguments = arguments });
                return true;
            }
            catch (Win32Exception) { return false; }
        }

        static void Log(string line)
        {
            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "oculyx-setup.log"), DateTime.Now.ToString("s") + "  " + line + Environment.NewLine); }
            catch (Exception) { }
        }

        [STAThread]
        static int Main(string[] args)
        {
            string exe = Application.ExecutablePath;
            string fileName = Path.GetFileName(exe);
            bool silent = Has(args, "--silent");

            if (fileName.StartsWith("OculyxTray", StringComparison.OrdinalIgnoreCase) || Has(args, "--tray"))
            {
                if (Has(args, "--uninstall")) return UninstallMode(silent);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                bool created;
                using (var m = new Mutex(true, @"Local\OculyxTray", out created))
                {
                    if (!created) return 0;
                    Application.Run(new TrayContext());
                }
                return 0;
            }

            if (Has(args, "--uninstall")) return UninstallMode(silent);

            Config cfg = Config.Read(exe);
            if (cfg.Name.Length == 0) cfg.Name = Environment.MachineName;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // debug aid: draw the window into a PNG and quit (used to check the layout without a screen)
            int ri = Array.IndexOf(args, "--render");
            if (ri >= 0 && ri + 1 < args.Length)
            {
                using (var f = new SetupForm(cfg, args.Length > ri + 2 && args[ri + 2] == "--demo-log"))
                {
                    f.Show();
                    Application.DoEvents();
                    Thread.Sleep(300);
                    Application.DoEvents();
                    using (var bmp = new Bitmap(f.Width, f.Height))
                    {
                        f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                        bmp.Save(args[ri + 1], System.Drawing.Imaging.ImageFormat.Png);
                    }
                }
                return 0;
            }

            if (!IsAdmin())
            {
                if (silent) { Log("Administrator rights are required for --silent."); return 5; }
                if (!Elevate(string.Join(" ", args), exe)) return 1223; // user cancelled UAC
                return 0;
            }

            if (silent) return SilentInstall(cfg);
            Application.Run(new SetupForm(cfg, false));
            return 0;
        }

        static int SilentInstall(Config cfg)
        {
            if (!cfg.Stamped) { Log("This file has no server settings stamped in; download it from the Oculyx web UI."); return 2; }
            if (!Check.Server(cfg.Server) || !Check.Token(cfg.Token) || !Check.Name(cfg.Name)) { Log("Invalid settings in this installer."); return 3; }
            var inst = new Installer();
            inst.OnLine = Log;
            inst.Install(cfg, false);
            return inst.Succeeded && !inst.Failed ? 0 : 1;
        }

        static int UninstallMode(bool silent)
        {
            string dir = Path.GetDirectoryName(Application.ExecutablePath);
            string script = Path.Combine(dir, "install.ps1");
            Config cfg = Config.Read(Application.ExecutablePath);

            // never delete the folder we are running from while running from it
            bool inProgramData = Application.ExecutablePath.IndexOf(@"\Oculyx\", StringComparison.OrdinalIgnoreCase) >= 0;
            if (inProgramData)
            {
                string tempExe = Path.Combine(Path.GetTempPath(), "OculyxUninstall-" + Guid.NewGuid().ToString("N") + ".exe");
                string tempPs = Path.Combine(Path.GetTempPath(), "oculyx-uninstall-" + Guid.NewGuid().ToString("N") + ".ps1");
                try
                {
                    File.Copy(Application.ExecutablePath, tempExe, true);
                    if (File.Exists(script)) File.Copy(script, tempPs, true);
                }
                catch (Exception) { }
                string args = "--uninstall" + (silent ? " --silent" : "");
                try { Process.Start(new ProcessStartInfo(tempExe, args) { UseShellExecute = true, Verb = IsAdmin() ? "open" : "runas" }); }
                catch (Win32Exception) { }
                return 0;
            }

            if (!IsAdmin()) { if (!silent) Elevate("--uninstall", Application.ExecutablePath); return 0; }

            string tmpScript = null;
            foreach (string f in Directory.GetFiles(Path.GetTempPath(), "oculyx-uninstall-*.ps1")) { tmpScript = f; break; }
            var inst = new Installer();
            inst.OnLine = Log;
            inst.Uninstall(tmpScript, cfg.Server.Length > 0 ? cfg.Server : null);
            if (tmpScript != null) { try { File.Delete(tmpScript); } catch (Exception) { } }
            if (!silent) MessageBox.Show(inst.Failed ? "Could not remove the agent:\n" + inst.LastError : "The Oculyx agent was removed.", "Oculyx", MessageBoxButtons.OK, inst.Failed ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            return inst.Failed ? 1 : 0;
        }
    }

    sealed class SetupForm : Form
    {
        readonly Config cfg;
        TextBox server, token, name, log;
        CheckBox allow;
        Button install, close;
        Label status;
        ProgressBar bar;
        Panel header;
        bool running;

        public SetupForm(Config c, bool demoLog)
        {
            cfg = c;
            Text = "Oculyx agent setup";
            ClientSize = new Size(560, 520);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = Theme.Ui(9.5f, FontStyle.Regular);
            using (var bmp = Theme.Mark(32, Theme.Accent)) Icon = Icon.FromHandle(bmp.GetHicon());

            header = new Panel { Left = 0, Top = 0, Width = ClientSize.Width, Height = 92, BackColor = Theme.Panel };
            header.Paint += delegate (object s, PaintEventArgs e)
            {
                using (var m = Theme.Mark(40, Theme.Accent)) e.Graphics.DrawImage(m, 28, 26, 40, 40);
                using (var b = new SolidBrush(Theme.Text)) e.Graphics.DrawString("Connect this PC to Oculyx", Theme.Ui(15f, FontStyle.Bold), b, 82, 22);
                using (var b = new SolidBrush(Theme.Muted)) e.Graphics.DrawString(cfg.Stamped ? cfg.Server : "Enter the address and token from the Oculyx web UI", Theme.Ui(9.5f, FontStyle.Regular), b, 84, 54);
                using (var p = new Pen(Theme.Line)) e.Graphics.DrawLine(p, 0, header.Height - 1, header.Width, header.Height - 1);
            };
            Controls.Add(header);

            int y = 112;
            if (!cfg.Stamped)
            {
                server = Field("Oculyx server address", "https://oculyx.example.com", ref y);
                token = Field("Enrollment token", "ocx_…", ref y);
            }
            name = Field("Name shown in Oculyx", "", ref y);
            name.Text = cfg.Name;

            allow = new CheckBox
            {
                Left = 28, Top = y, Width = 500, Height = 24, Text = "Let Oculyx start / stop / restart Docker containers on this PC",
                ForeColor = Theme.Muted, BackColor = Theme.Bg, Checked = cfg.AllowActions, FlatStyle = FlatStyle.Standard
            };
            Controls.Add(allow);
            y += 38;

            install = new Button
            {
                Left = 28, Top = y, Width = 150, Height = 38, Text = "Install", FlatStyle = FlatStyle.Flat,
                BackColor = Theme.Accent, ForeColor = Theme.AccentInk, Font = Theme.Ui(10f, FontStyle.Bold), Cursor = Cursors.Hand
            };
            install.FlatAppearance.BorderSize = 0;
            install.Click += delegate { Start(); };
            Controls.Add(install);

            close = new Button
            {
                Left = 190, Top = y, Width = 100, Height = 38, Text = "Close", FlatStyle = FlatStyle.Flat,
                BackColor = Theme.Panel, ForeColor = Theme.Text, Cursor = Cursors.Hand
            };
            close.FlatAppearance.BorderColor = Theme.Line;
            close.Click += delegate { Close(); };
            Controls.Add(close);

            bar = new ProgressBar { Left = 28, Top = y + 52, Width = 504, Height = 6, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 0, Visible = false };
            Controls.Add(bar);

            status = new Label { Left = 28, Top = y + 66, Width = 504, Height = 22, ForeColor = Theme.Muted, BackColor = Theme.Bg, Text = "Needs administrator rights; Windows will ask once." };
            Controls.Add(status);

            log = new TextBox
            {
                Left = 28, Top = y + 94, Width = 504, Height = ClientSize.Height - (y + 94) - 24, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                BackColor = Theme.Panel, ForeColor = Theme.Muted, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Consolas", 9f)
            };
            Controls.Add(log);
            ActiveControl = install;

            if (demoLog)
            {
                log.Text = "==> Checking requirements\r\n  + Windows 10.0.26100 (x64)\r\n  + Oculyx server reachable\r\n\r\n==> Installing Node.js 24 (official build)\r\n  + Node.js v24.22.0\r\n\r\n==> Starting the agent (scheduled task)\r\n  + Connected to Oculyx";
                status.Text = "Connected. Oculyx is now monitoring this PC.";
                status.ForeColor = Theme.Ok;
            }
        }

        TextBox Field(string label, string hint, ref int y)
        {
            Controls.Add(new Label { Left = 28, Top = y, Width = 500, Height = 18, Text = label, ForeColor = Theme.Muted, BackColor = Theme.Bg });
            var t = new TextBox { Left = 28, Top = y + 22, Width = 504, Height = 28, BackColor = Theme.Panel, ForeColor = Theme.Text, BorderStyle = BorderStyle.FixedSingle, Font = Theme.Ui(10f, FontStyle.Regular) };
            Controls.Add(t);
            y += 62;
            return t;
        }

        void Append(string line)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string>(Append), line); return; }
            log.AppendText(line + "\r\n");
        }

        void Start()
        {
            if (running) return;
            var c = new Config
            {
                Server = (server != null ? server.Text.Trim().TrimEnd('/') : cfg.Server),
                Token = (token != null ? token.Text.Trim() : cfg.Token),
                Name = name.Text.Trim(),
                AllowActions = allow.Checked
            };
            if (!Check.Server(c.Server)) { Fail("That server address does not look right (use http:// or https://)."); return; }
            if (!Check.Token(c.Token)) { Fail("The token looks malformed. Copy it again from Oculyx."); return; }
            if (!Check.Name(c.Name)) { Fail("The name may only contain letters, numbers, spaces, dot, dash and underscore."); return; }

            running = true;
            install.Enabled = false;
            allow.Enabled = false;
            name.Enabled = false;
            bar.Visible = true;
            bar.MarqueeAnimationSpeed = 28;
            status.ForeColor = Theme.Muted;
            status.Text = "Installing... this takes about a minute.";
            log.Clear();

            var inst = new Installer();
            inst.OnLine = Append;
            var t = new Thread(delegate ()
            {
                try { inst.Install(c, true); }
                catch (Exception ex) { inst.Failed = true; inst.LastError = ex.Message; }
                BeginInvoke(new Action(delegate { Done(inst); }));
            });
            t.IsBackground = true;
            t.Start();
        }

        void Fail(string message)
        {
            status.ForeColor = Theme.Bad;
            status.Text = message;
        }

        void Done(Installer inst)
        {
            running = false;
            bar.MarqueeAnimationSpeed = 0;
            bar.Visible = false;
            if (inst.Succeeded && !inst.Failed)
            {
                status.ForeColor = Theme.Ok;
                status.Text = "Connected. Oculyx is now monitoring this PC.";
                install.Text = "Done";
                install.Enabled = true;
                install.Click += delegate { Close(); };
            }
            else
            {
                status.ForeColor = Theme.Bad;
                status.Text = inst.Failed && inst.LastError.Length > 0 ? inst.LastError : "The agent did not confirm the connection. See the log below.";
                install.Enabled = true;
                allow.Enabled = true;
                name.Enabled = true;
                install.Text = "Try again";
            }
        }
    }

    /// <summary>Tray icon showing whether the local agent is connected (reads the status file the agent keeps up to date).</summary>
    sealed class TrayContext : ApplicationContext
    {
        readonly NotifyIcon icon = new NotifyIcon();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly ToolStripMenuItem header = new ToolStripMenuItem("Oculyx agent");
        readonly string statusPath;
        string lastState = "";
        string server = "";

        public TrayContext()
        {
            statusPath = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "status.json");
            var menu = new ContextMenuStrip();
            header.Enabled = false;
            menu.Items.Add(header);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open Oculyx dashboard", null, delegate
            {
                if (server.Length > 0) { try { Process.Start(server); } catch (Exception) { } }
            });
            menu.Items.Add("Uninstall agent...", null, delegate { Remove(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Hide icon", null, delegate { ExitThread(); });
            icon.ContextMenuStrip = menu;
            icon.Visible = true;
            icon.DoubleClick += delegate { if (server.Length > 0) { try { Process.Start(server); } catch (Exception) { } } };
            timer.Interval = 5000;
            timer.Tick += delegate { Refresh(); };
            timer.Start();
            Refresh();
        }

        void Refresh()
        {
            string state = "off";
            string text = "Oculyx agent: not running";
            try
            {
                var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(statusPath));
                object s, u, c;
                if (d.TryGetValue("server", out s) && s != null) server = s.ToString();
                long updated = d.TryGetValue("updated", out u) ? Convert.ToInt64(u) : 0;
                long now = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds;
                bool fresh = now - updated < 90000;
                bool connected = d.TryGetValue("connected", out c) && c is bool && (bool)c;
                if (fresh && connected) { state = "ok"; text = "Oculyx agent: connected"; }
                else if (fresh) { state = "warn"; text = "Oculyx agent: reconnecting..."; }
            }
            catch (Exception) { }
            if (state == lastState) return;
            lastState = state;
            Color col = state == "ok" ? Theme.Ok : state == "warn" ? Color.FromArgb(251, 191, 36) : Theme.Bad;
            Icon old = icon.Icon;
            using (var bmp = Theme.Mark(32, col)) icon.Icon = Icon.FromHandle(bmp.GetHicon());
            if (old != null) Native.DestroyIcon(old.Handle);
            icon.Text = text;
            header.Text = text + (server.Length > 0 ? "  -  " + server : "");
        }

        void Remove()
        {
            if (MessageBox.Show("Remove the Oculyx agent from this PC?\nThis computer will stop being monitored.", "Oculyx", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Program.Elevate("--uninstall", Application.ExecutablePath);
            icon.Visible = false;
            ExitThread();
        }

        protected override void ExitThreadCore()
        {
            timer.Stop();
            icon.Visible = false;
            base.ExitThreadCore();
        }
    }
}
