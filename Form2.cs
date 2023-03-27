using System;
using System.Windows.Forms;
using System.Media;
using System.Net;
using System.Threading;

namespace Cryptocomm
{
    public partial class Form2 : Form
    {
        Functions functions = new Functions();

        public void InitAddrs()
        {
            Console.WriteLine("Addr init..");
            var addrs = functions.GetAddrs();
            int i = 0;
            if (addrs.Count == 0)
            {
                this.listBox1.Items.Clear();
                this.listBox1.Items.Add("Никого не найдено");
                this.listBox1.Items.Add("Возможно, отключен");
                this.listBox1.Items.Add("протокол SMB1?");
            }
            foreach (string addr in addrs)
            {
                if (i == 0){
                    this.listBox1.Items.Clear();
                }
                this.listBox1.Items.Add(addr);
                i += 1;
            }
        }

        public Form2()
        {
            InitializeComponent();
        }

        private void Form2_FormClosed(object sender, FormClosedEventArgs e)
        {
            Application.Exit();
        }

        public void startssl()
        {
            SslTcpServer.RunServer("first.pfx");
        }

        private void Form2_Shown(object sender, EventArgs e)
        {
            var th = new Thread(startssl);
            th.Start();
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if(listBox1.Items[0].ToString() == "Никого не найдено")
            {
                try
                {
                    using (var soundPlayer = new SoundPlayer(@"c:\Windows\Media\Windows Ding.wav"))
                    {
                        soundPlayer.Play(); // can also use soundPlayer.PlaySync()
                    }
                }
                catch (Exception err)
                {
                    Console.WriteLine(err);
                }
            }
        }

        private void listBox1_SelectedIndexChanged_1(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            listBox1.Items.Clear();
            listBox1.Items.Add("** Обновление **");
            InitAddrs();
        }

        public void startsslc(string actualip)
        {
            SslTcpClient.RunClient(actualip, "publickey.cer");
        }

        public static Thread cth = null;
        private void button2_Click(object sender, EventArgs e)
        {

            if(button2.Text == "Прервать")
            {
                cth.Abort();
                button2.Text = "Написать";
                listBox1.Enabled = true;
                return;
            }
            DialogResult res = MessageBox.Show("Вы хотите начать диалог с " + listBox1.SelectedItem.ToString() + "?", "Внимание", MessageBoxButtons.YesNo);
            if (res == DialogResult.Yes)
            {
                Console.WriteLine("Общаемся с " + listBox1.SelectedItem.ToString());
                IPAddress[] addresslist = Dns.GetHostAddresses(listBox1.SelectedItem.ToString());
                var actualip = "";
                foreach (IPAddress theaddress in addresslist)
                {
                    if(theaddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        actualip = theaddress.ToString();
                        break;
                    }
                }

                if (actualip == "")
                {
                    MessageBox.Show("Не удалось получить IP-адрес версии 4 компьютера " + listBox1.SelectedItem.ToString() + ". Возможно, клиент не в сети.", "Ошибка");
                }
                else
                {
                    if (Functions.PingHost(actualip))
                    {
                        cth = new Thread(() => startsslc(actualip));
                        cth.Start(); 
                        button2.Text = "Прервать";
                        listBox1.Enabled = false;
                    }
                    else
                    {
                        MessageBox.Show("Не удалось обратиться к компьютеру" + listBox1.SelectedItem.ToString() + " (IP адрес "+actualip+"). Возможно, клиент не в сети.", "Ошибка");
                    }
                }
            }
            else
            {
                Console.WriteLine("Отмена");
            }
        }
    }
}
