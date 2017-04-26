using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrettyGoodPrivacy_Key
{
    class Program
    {
        static void Main(string[] args)
        {
            //RSA密鑰產生器 
            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            //Key 構造使用參數        
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 1024, 25));  //1024 key 的長度
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            char[] password = "~!@#$%^&".ToCharArray(); //私鑰的密碼
            Stream out1, out2;
            out1 = File.Create(@"D:\PGP\Sample_priv.asc");//私鑰放置位置          
            out2 = File.Create(@"D:\PGP\Sample_pub.asc"); //公鑰放置位置
            ExportKeyPair(out1, out2, kp.Public,
            kp.Private, "INTEL0620", password, true);
        }

        //傳入參數依序如下
        //(1) Private key 的 FileStream ,
        //(2) Public key 的 FileStream, 
        //(3) 由  Bouncy Castle  產生的 publuic Key , 
        //(4) 由 Bouncy Castle產生的 private key , 
        //(5) 使用者名稱 String , 
        //(6) armor 不明.......範例設為true
        private static void ExportKeyPair(Stream secretOut, Stream publicOut, AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey,
                                            string identity, char[] passPhrase, bool armor)
        {
            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }
            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                PublicKeyAlgorithmTag.RsaGeneral,
                publicKey,
                privateKey,
                DateTime.UtcNow,
                identity,
                SymmetricKeyAlgorithmTag.Cast5,
                passPhrase,
                null,
                null,
                new SecureRandom()
                );
            secretKey.Encode(secretOut);
            if (armor)
            {
                secretOut.Close();
                publicOut = new ArmoredOutputStream(publicOut);
            }
            PgpPublicKey key = secretKey.PublicKey;
            key.Encode(publicOut);
            if (armor)
            {
                publicOut.Close();
            }
        }
    }
}
