using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace crypto_net
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (this.textBox1.Text != "")
            {
                this.textBox2.Text = criptografar_CInfo(this.textBox1.Text);
            }
        }


        private string criptografar_CInfo(string dados)
        {
            //return criptografar_CI(dados, "v7Tbres9"); //connection string
            return criptografar_CI(dados, "gB40FL09");
        }

        private string criptografar_CI(string dados, string senha)
        {

            byte[] b = Encoding.UTF8.GetBytes(dados);
            byte[] pw = Encoding.UTF8.GetBytes(senha);

            RijndaelManaged rm = new RijndaelManaged();

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(senha, new MD5CryptoServiceProvider().ComputeHash(pw));
            rm.Key = pdb.GetBytes(32);
            rm.IV = pdb.GetBytes(16);
            rm.BlockSize = 128;
            rm.Padding = PaddingMode.PKCS7;

            MemoryStream ms = new MemoryStream();

            CryptoStream cryptStream = new CryptoStream(ms, rm.CreateEncryptor(rm.Key, rm.IV), CryptoStreamMode.Write);
            cryptStream.Write(b, 0, b.Length);
            cryptStream.FlushFinalBlock();
            return System.Convert.ToBase64String(ms.ToArray());
        }


    }
}
