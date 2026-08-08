using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

public class ScannerForm : Form
{
    private ComboBox cboSubnet;
    private Button btnScan;
    private Button btnStop;
    private DataGridView gridResults;
    private Label lblStatus;
    private DataTable table;
    private ContextMenuStrip contextMenu;
    private CancellationTokenSource cts;
    private ConcurrentDictionary<string, bool> discoveredIps;

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    public static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int physicalAddrLen);

    [STAThread]
    public static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new ScannerForm());
    }

    public ScannerForm()
    {
        this.Text = "Fast Subnet & Vendor Scanner";
        this.Size = new Size(740, 500);
        this.StartPosition = FormStartPosition.CenterScreen;

        // Embedded icon setup
        try
        {
            this.Icon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        }
        catch { }

        Label lblSubnet = new Label() { Text = "Subnet:", Location = new Point(12, 15), AutoSize = true };

        cboSubnet = new ComboBox() { Location = new Point(70, 12), Width = 160, DropDownStyle = ComboBoxStyle.DropDown };
        PopulateSubnetDropdown();

        btnScan = new Button() { Text = "Scan Subnet", Location = new Point(240, 10), Width = 90 };
        btnScan.Click += async (s, e) => await StartTwoPassScanAsync();

        btnStop = new Button() { Text = "Stop", Location = new Point(335, 10), Width = 60, Enabled = false };
        btnStop.Click += (s, e) => StopScan();

        this.AcceptButton = btnScan;

        lblStatus = new Label() { Text = "Ready", Location = new Point(405, 15), AutoSize = true };

        contextMenu = new ContextMenuStrip();
        var copyIpItem = contextMenu.Items.Add("Copy IP Address");
        copyIpItem.Click += (s, e) => CopySelectedIp();

        gridResults = new DataGridView()
        {
            Location = new Point(12, 45),
            Size = new Size(700, 400),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            ReadOnly = true,
            AllowUserToAddRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = true,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            ContextMenuStrip = contextMenu
        };

        gridResults.CellDoubleClick += (s, e) =>
        {
            if (e.RowIndex >= 0)
            {
                CopySelectedIp();
            }
        };

        table = new DataTable();
        table.Columns.Add("IP Address", typeof(string));
        table.Columns.Add("Host Name", typeof(string));
        table.Columns.Add("Vendor / Hardware", typeof(string));
        table.Columns.Add("MAC Address", typeof(string));
        table.Columns.Add("Response (ms)", typeof(string));
        gridResults.DataSource = table;

        this.Controls.Add(lblSubnet);
        this.Controls.Add(cboSubnet);
        this.Controls.Add(btnScan);
        this.Controls.Add(btnStop);
        this.Controls.Add(lblStatus);
        this.Controls.Add(gridResults);

        this.Shown += async (s, e) => await StartTwoPassScanAsync();
    }

    private void PopulateSubnetDropdown()
    {
        List<string> subnets = GetLocalSubnetPrefixes();
        cboSubnet.Items.Clear();

        foreach (string subnet in subnets)
        {
            cboSubnet.Items.Add(subnet);
        }

        if (cboSubnet.Items.Count > 0)
            cboSubnet.SelectedIndex = 0;
        else
            cboSubnet.Text = "192.168.1";
    }

    private void CopySelectedIp()
    {
        if (gridResults.CurrentRow != null)
        {
            string ip = gridResults.CurrentRow.Cells[0].Value.ToString();
            Clipboard.SetText(ip);
            lblStatus.Text = string.Format("Copied IP: {0}", ip);
        }
    }

    private async Task StartTwoPassScanAsync()
    {
        string prefix = cboSubnet.Text.Trim().TrimEnd('.');
        if (prefix.Split('.').Length != 3)
        {
            MessageBox.Show("Please enter or select a valid 3-octet subnet prefix (e.g., 192.168.1).", "Invalid Input");
            return;
        }

        btnScan.Enabled = false;
        btnStop.Enabled = true;
        table.Rows.Clear();

        cts = new CancellationTokenSource();
        CancellationToken token = cts.Token;
        discoveredIps = new ConcurrentDictionary<string, bool>();

        try
        {
            // --- PASS 1: Fast Ping Async (Instant Results) ---
            lblStatus.Text = "Pass 1/2: Fast ping scanning " + prefix + ".x...";

            var fastTasks = Enumerable.Range(1, 254)
                .Select(i => FastPingHostAsync(string.Format("{0}.{1}", prefix, i), token))
                .ToArray();

            await Task.WhenAll(fastTasks);

            if (token.IsCancellationRequested) return;

            // --- PASS 2: Deep ARP Scan for Missing Devices (Packard Bell, etc.) ---
            int fastCount = table.Rows.Count;
            lblStatus.Text = string.Format("Pass 2/2: Deep ARP check for hidden devices ({0} found so far)...", fastCount);

            var remainingIps = Enumerable.Range(1, 254)
                .Select(i => string.Format("{0}.{1}", prefix, i))
                .Where(ip => !discoveredIps.ContainsKey(ip))
                .ToList();

            await Task.Run(() =>
            {
                Parallel.ForEach(remainingIps, new ParallelOptions { MaxDegreeOfParallelism = 32, CancellationToken = token }, ip =>
                {
                    if (token.IsCancellationRequested) return;

                    string mac = GetMacAddress(ip);
                    if (mac != "N/A" && discoveredIps.TryAdd(ip, true))
                    {
                        string hostName = ResolveHostName(ip);
                        string vendor = LookupVendor(mac);

                        this.BeginInvoke((Action)(() =>
                        {
                            table.Rows.Add(ip, hostName, vendor, mac, "0 (ARP)");
                        }));
                    }
                });
            }, token);
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (cts.IsCancellationRequested)
                lblStatus.Text = string.Format("Scan stopped. Found {0} host(s).", table.Rows.Count);
            else
                lblStatus.Text = string.Format("Done. Found {0} host(s) total.", table.Rows.Count);

            btnScan.Enabled = true;
            btnStop.Enabled = false;
        }
    }

    private async Task FastPingHostAsync(string ip, CancellationToken token)
    {
        if (token.IsCancellationRequested) return;

        using (Ping p = new Ping())
        {
            try
            {
                PingReply reply = await p.SendPingAsync(ip, 400);
                if (reply != null && reply.Status == IPStatus.Success)
                {
                    if (discoveredIps.TryAdd(ip, true))
                    {
                        string macAddress = GetMacAddress(ip);
                        string vendor = LookupVendor(macAddress);
                        string hostName = await Task.Run(() => ResolveHostName(ip), token);

                        if (token.IsCancellationRequested) return;

                        this.BeginInvoke((Action)(() =>
                        {
                            table.Rows.Add(ip, hostName, vendor, macAddress, reply.RoundtripTime.ToString());
                        }));
                    }
                }
            }
            catch { }
        }
    }

    private void StopScan()
    {
        if (cts != null && !cts.IsCancellationRequested)
        {
            cts.Cancel();
            lblStatus.Text = "Stopping scan...";
            btnStop.Enabled = false;
        }
    }

    private string ResolveHostName(string ip)
    {
        string name = GetNetBiosName(ip);
        if (!string.IsNullOrEmpty(name)) return name;

        name = QueryLlmnrOrDns(ip);
        if (!string.IsNullOrEmpty(name) && name != "N/A") return name;

        try
        {
            IPHostEntry entry = Dns.GetHostEntry(ip);
            return entry.HostName;
        }
        catch
        {
            return "N/A";
        }
    }

    private string QueryLlmnrOrDns(string ip)
    {
        try
        {
            IPHostEntry entry = Dns.GetHostEntry(ip);
            if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != ip)
            {
                return entry.HostName;
            }
        }
        catch { }
        return null;
    }

    private string GetNetBiosName(string ip)
    {
        try
        {
            byte[] request = new byte[] {
                0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01
            };

            using (UdpClient client = new UdpClient())
            {
                client.Client.SendTimeout = 250;
                client.Client.ReceiveTimeout = 250;
                IPEndPoint ep = new IPEndPoint(IPAddress.Parse(ip), 137);

                client.Send(request, request.Length, ep);
                byte[] response = client.Receive(ref ep);

                if (response != null && response.Length > 57)
                {
                    int nameCount = response[56];
                    if (nameCount > 0)
                    {
                        string rawName = Encoding.ASCII.GetString(response, 57, 15).Trim();
                        if (!string.IsNullOrEmpty(rawName))
                            return rawName;
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private string GetMacAddress(string ip)
    {
        try
        {
            IPAddress dst = IPAddress.Parse(ip);
            byte[] ipBytes = dst.GetAddressBytes();
            int destIpInt = BitConverter.ToInt32(ipBytes, 0);

            byte[] macAddr = new byte[6];
            int len = macAddr.Length;
            int res = SendARP(destIpInt, 0, macAddr, ref len);

            if (res == 0)
            {
                string[] bytes = new string[6];
                for (int i = 0; i < 6; i++)
                    bytes[i] = macAddr[i].ToString("X2");

                return string.Join(":", bytes);
            }
        }
        catch { }
        return "N/A";
    }

    private string LookupVendor(string mac)
    {
        if (string.IsNullOrEmpty(mac) || mac == "N/A" || mac.Length < 8)
            return "Unknown";

        string prefix = mac.Substring(0, 8).Replace(":", "").ToUpper();

        Dictionary<string, string> ouiMap = new Dictionary<string, string>()
        {
            { "000393", "Apple" }, { "000502", "Apple" }, { "000A27", "Apple" }, { "000D93", "Apple" },
            { "0010FA", "Apple" }, { "001124", "Apple" }, { "001408", "Apple" }, { "0016CB", "Apple" },
            { "0017F2", "Apple" }, { "0019E3", "Apple" }, { "001B63", "Apple" }, { "001C10", "Apple" },
            { "001D4F", "Apple" }, { "001E52", "Apple" }, { "001EC2", "Apple" }, { "001F5B", "Apple" },

            { "0000F0", "Samsung" }, { "000278", "Samsung" }, { "0007AB", "Samsung" }, { "000918", "Samsung" },

            { "000C29", "VMware" }, { "00155D", "Microsoft Hyper-V" }, { "001C42", "Parallels" },
            { "005056", "VMware" }, { "080027", "Oracle VirtualBox" },

            { "000420", "Cisco" }, { "00055F", "Cisco" }, { "0007EB", "Cisco" },

            { "001302", "Intel" }, { "001320", "Intel" }, { "0013E8", "Intel" }, { "001500", "Intel" },

            { "0017C4", "Quanta / Packard Bell" }, { "74F06D", "Asus / AzureWave" }, { "A28869", "Private/Random MAC" },
            { "001801", "LG Electronics" }, { "0019A4", "Sony" }, { "000B86", "Aruba" },
            { "001310", "Linksys" }, { "001E2A", "NETGEAR" }, { "001D0F", "TP-LINK" },
            { "001E8C", "ASUS" }, { "B827EB", "Raspberry Pi" }, { "DCA632", "Raspberry Pi" },
            { "E45F01", "Raspberry Pi" }, { "28CDC1", "Amazon" }, { "001A11", "Google" }
        };

        if (ouiMap.ContainsKey(prefix))
            return ouiMap[prefix];

        char secondChar = prefix[1];
        if (secondChar == '2' || secondChar == '6' || secondChar == 'A' || secondChar == 'E')
            return "Private/Random MAC (Mobile Device)";

        return "Unknown Vendor";
    }

    private List<string> GetLocalSubnetPrefixes()
    {
        List<string> prefixes = new List<string>();
        try
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up &&
                   (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet))
                {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork &&
                            !IPAddress.IsLoopback(ip.Address) &&
                            !ip.Address.ToString().StartsWith("169.254"))
                        {
                            string[] parts = ip.Address.ToString().Split('.');
                            string prefix = string.Format("{0}.{1}.{2}", parts[0], parts[1], parts[2]);

                            if (!prefixes.Contains(prefix))
                            {
                                prefixes.Add(prefix);
                            }
                        }
                    }
                }
            }
        }
        catch { }

        return prefixes;
    }
}