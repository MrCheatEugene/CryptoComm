using System;
using System.Windows.Forms;
using static System.Net.HttpListener;
namespace Cryptocomm
{
    public partial class Form1 : Form
    {
        Functions functions = new Functions();
        public Form1()
        {
            InitializeComponent();
        }

        private void label1_Click(object sender, EventArgs e)
        {
            MessageBox.Show("MD5 хэш сборки: " + functions.MD5OfBuild(),"Отладка");
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (!IsSupported)
            {
                MessageBox.Show("Для работы CryptoComm требуется ОС не ниже Windows XP SP2 или Windows Server 2003.", "Ошибка");
                Application.Exit();
                return;
            }
            Form1.ActiveForm.Hide();
            var form = new Form2();
            form.InitAddrs();
            form.Show();
        }
    }
}
