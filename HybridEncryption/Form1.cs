using Encryption;
using System;
using System.IO;
using System.IO.Compression;
using System.Windows.Forms;

namespace HybridEncryption
{
    public partial class Form1 : Form
    {
        
        public Form1()
        {
            InitializeComponent();
        }





        private void button1_Click(object sender, EventArgs e)
        {
            Sodium.KeyPair alice = Sodium.PublicKeyBox.GenerateKeyPair();
            Sodium.KeyPair bob = Sodium.PublicKeyBox.GenerateKeyPair();
            Sodium.KeyPair SiningKey = Sodium.PublicKeyAuth.GenerateKeyPair(); //64 byte private key | 32 byte public key

            Encryption.Encryption Cryptor = new Encryption.Encryption();

            byte[] inFile = File.ReadAllBytes(textBox1.Text);

            byte[] encryptedFile = Cryptor.Encrypt(inFile, Convert.ToBase64String(alice.PrivateKey), Convert.ToBase64String(bob.PublicKey));

            byte[] signature = Cryptor.Sign(encryptedFile, Convert.ToBase64String(SiningKey.PrivateKey));

            byte[] signedFile = Cryptor.AddSignature(encryptedFile, signature);

            File.WriteAllBytes(textBox1.Text + ".CryptSign", signedFile);
            inFile = encryptedFile = signature = null;

            

            byte[] signature2 = Cryptor.GetSignature(signedFile);

            byte[] file2 = Cryptor.RemoveSignature(signedFile);

            if (Cryptor.VerifySign(file2, signature2, Convert.ToBase64String(SiningKey.PublicKey)))
            {
                byte[] decrypted = Cryptor.Decrypt(file2, Convert.ToBase64String(bob.PrivateKey), Convert.ToBase64String(alice.PublicKey));
                File.WriteAllBytes(textBox1.Text + ".decrypt", decrypted);
            }
            else
            {
                throw new Exception("FUCK");
            }
           
        }
    }
}
