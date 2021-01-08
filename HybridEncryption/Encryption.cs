using System;
using System.IO;

namespace Encryption
{
    class Encryption
    {

        public bool Encrypt(string inPath, string outPath, string privKey, string pubKey)
        {
            //read in file
            byte[] message = File.ReadAllBytes(inPath);
            byte[] encrypted = Encrypt(message, privKey, pubKey);
            if(encrypted != null)
            {
                File.WriteAllBytes(outPath, encrypted);
                return true;
            }
            return false;
        }

        public byte[] Encrypt(byte[] inFile, string privKey, string pubKey)
        {


            //Generate random key and nonce
            byte[] nonce = Sodium.SecretBox.GenerateNonce(); //24 bytes
            byte[] key = Sodium.SecretBox.GenerateKey(); //32 bytes



            byte[] cipherText;
            byte[] nonce2;
            byte[] encrypted;
            try
            {
                //encrypt file with symetric encryption
                cipherText = Sodium.SecretBox.Create(inFile, nonce, key);

                //Encrypt the key with symetrical encryption
                nonce2 = Sodium.PublicKeyBox.GenerateNonce(); //24 bytes
                encrypted = Sodium.PublicKeyBox.Create(key, nonce2, Convert.FromBase64String(privKey), Convert.FromBase64String(pubKey)); //48 bytes
            }
            catch (Exception e)
            {
                Console.WriteLine("Encryption Failed: " + e.Message);
                return null;
            }


            //copy nonce and cipher text into array
            byte[] outText = new byte[cipherText.Length + 24];
            Buffer.BlockCopy(nonce, 0, outText, 0, 24);
            Buffer.BlockCopy(cipherText, 0, outText, 24, cipherText.Length);

            //prepare final file
            byte[] final = new byte[outText.Length + 24 + 48];
            Buffer.BlockCopy(nonce2, 0, final, 0, 24);
            Buffer.BlockCopy(encrypted, 0, final, 24, 48);
            Buffer.BlockCopy(outText, 0, final, 24 + 48, outText.Length);

            return final;
        }

        public bool Decrypt(string inPath, string outPath, string privKey, string pubKey)
        {
            //read in file
            byte[] message = File.ReadAllBytes(inPath);
            byte[] decrypted = Decrypt(message, privKey, pubKey);
            if (decrypted != null)
            {
                File.WriteAllBytes(outPath, decrypted);
                return true;
            }
            return false;
        }

        public byte[] Decrypt(byte[] inFile, string privKey, string pubKey)
        {
            
            //extract the different parts
            byte[] nonce = new byte[24];
            byte[] encrypted = new byte[48];
            byte[] cipherTextNonce = new byte[inFile.Length - 48 - 24];
            Buffer.BlockCopy(inFile, 0, nonce, 0, 24);
            Buffer.BlockCopy(inFile, 24, encrypted, 0, 48);
            Buffer.BlockCopy(inFile, 24 + 48, cipherTextNonce, 0, inFile.Length - 48 - 24);

            byte[] decrypted;
            try
            {
                //decrypt key with symetrical encryption
                decrypted = Sodium.PublicKeyBox.Open(encrypted, nonce, Convert.FromBase64String(privKey), Convert.FromBase64String(pubKey));
            }
            catch (Exception e)
            {
                Console.WriteLine("Asymetrical Decryption Failed: " + e.Message);
                return null;
            }

            //extract the ciphertext and nonce for the symetrical encryption
            byte[] nonce2 = new byte[24];
            byte[] cipherText = new byte[cipherTextNonce.Length - 24];
            Buffer.BlockCopy(cipherTextNonce, 0, nonce2, 0, 24);
            Buffer.BlockCopy(cipherTextNonce, 24, cipherText, 0, cipherTextNonce.Length - 24);

            byte[] output;
            try
            {
                //decrypt symetrical encryption
                output = Sodium.SecretBox.Open(cipherText, nonce2, decrypted);
            }
            catch (Exception e)
            {
                Console.WriteLine("Symetrical Decryption Failed: " + e.Message);
                return null;
            }

            return output;
        }

        public byte[] Sign(string inPath, string privKey) => Sign(File.ReadAllBytes(inPath), privKey);

        public byte[] Sign(byte[] inFile, string privKey)
        {
            byte[] fileHash = Sodium.GenericHash.Hash(inFile, null, 64);
            byte[] privateKey = Convert.FromBase64String(privKey);
            return Sodium.PublicKeyAuth.SignDetached(fileHash, privateKey);
        }

        public bool VerifySign(string inPath, byte[] signature, string pubKey) => VerifySign(File.ReadAllBytes(inPath), signature, pubKey);

        public bool VerifySign(byte[] inFile, byte[] signature, string pubKey)
        {
            byte[] fileHash = Sodium.GenericHash.Hash(inFile, null, 64);
            return Sodium.PublicKeyAuth.VerifyDetached(signature, fileHash, Convert.FromBase64String(pubKey));
        }

        public void AddSignature(string inPath, string outPath, byte[] signature) => File.WriteAllBytes(outPath, AddSignature(File.ReadAllBytes(inPath), signature));

        public byte[] AddSignature(byte[] inFile, byte[] signature)
        {
            byte[] outFile = new byte[inFile.Length + 64];
            Buffer.BlockCopy(signature, 0, outFile, 0, 64);
            Buffer.BlockCopy(inFile, 0, outFile, 64, inFile.Length);
            return outFile;
        }

        public void RemoveSignature(string inPath, string outPath) => File.WriteAllBytes(outPath, RemoveSignature(File.ReadAllBytes(inPath)));

        public byte[] RemoveSignature(byte[] inFile)
        {
            byte[] outFile = new byte[inFile.Length - 64];
            Buffer.BlockCopy(inFile, 64, outFile, 0, inFile.Length - 64);
            return outFile;
        }

        public void GetSignature(string inPath, string outPath) => File.WriteAllBytes(outPath, GetSignature(File.ReadAllBytes(inPath)));

        public byte[] GetSignature(byte[] inFile)
        {
            byte[] outFile = new byte[64];
            Buffer.BlockCopy(inFile, 0, outFile, 0,64);
            return outFile;
        }
    }
}
