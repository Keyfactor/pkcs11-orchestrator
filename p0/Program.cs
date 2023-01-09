using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using pkcs11_orchestrator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace p0
{
    class Program
    {
        static void Main(string[] args)
        {
            string apiKey = "ZjkzNTk0OGItYjUxZS00NjdiLWI4Y2QtMGJkZGVmNTY0ZWVjOnFMQVdJLV9JY2x1eFh4RkJiekdQMDJja0tQMFJQRnRULW50bmJWb09QLWFmaXR5N2ZVSW5uMnVJam14dnVPa2ZLcG9sLUtTTXNGNG95ekI0Ujhwcld3";
            Console.WriteLine("Test running pkcs11 ---");
            //var p11 = new Pkcs11Client(@"C:\Program Files\Fortanix\KmsClient\FortanixKmsPkcs11.dll");
            var p11 = new Pkcs11Client(@"C:\SoftHSM2\lib\softhsm2-x64.dll");
            var slot = p11.GetOpenSlot();
            p11.PrintSlotContents(slot);
            string pin = "5678";
            var session = p11.LogInToSlot(slot, pin);
            IObjectHandle pubKey, privKey;
            Pkcs11Client.GenerateKeyPair(session, out pubKey, out privKey);
            var csr = p11.CreateCsr(session, pubKey, privKey);
            Console.WriteLine("Generated CSR with keys in HSM:");
            Console.WriteLine(csr);

            var ckaId = session.GetAttributeValue(pubKey, new List<CKA> { CKA.CKA_ID })[0].GetValueAsByteArray();
            Console.WriteLine($"CKA ID for KeyPair: {ckaId}");

            var pemCert = @"-----BEGIN CERTIFICATE-----
MIIDbzCCAlegAwIBAgIQNbJx732mM7dICDLS3wfsEjANBgkqhkiG9w0BAQsFADA+
MRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVkYnJzazEO
MAwGA1UEAxMFTVJDQTAwHhcNMTkwNTEwMTU1MjI1WhcNMjUwNTEwMTYwMjI1WjA+
MRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFTATBgoJkiaJk/IsZAEZFgVkYnJzazEO
MAwGA1UEAxMFTVJDQTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/
9jCxQjccAVDdTUYxlrksJFLALSdMzjGHq61qk5qy7QDxXDt7qPcwzFuJJVl5Dej/
fsHoBZXIAOZsJfr3x+Ft81fkNoU4sL2VJVA92902dG1g/A9ztT2hzTYYnQSz7JDD
4W3n5nN0i2reLRzC68bo8TKDlQs+LZJQ2teDWe6ufoupP+8s41xDM1BkOL9AkllD
jk4tXQwhkH7/340bu9MTgcQ1LrHiYA72SIIIDjPe+jwrFGhqEI5f1EhoS1CLbOIL
6Ba3Eluyux6/TkeDDb8NwqLZntXLSmstROx38MA9wP+YN+AZ2ZuZOpgHfmW/JuPO
HoXC5j+HXiN9AoFklSR5AgMBAAGjaTBnMBMGCSsGAQQBgjcUAgQGHgQAQwBBMA4G
A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS3qqWAXF+7
BFeo/pshAZt8vQq9EDAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQsFAAOC
AQEAtNZpXdGlkZiC5Ic+LqJSHCEuuXE/9gD/YxiBMYXdARvstLpjKTiJNZuB4Hal
7NIHgO4W92qp/3TZwps+xTYOcrtCwU2tsFmRLM9tagrLHdFAJQCkhNlefAUdVdGF
5zZJhdUe0lGQSqrToWLB+48QTJV0/tSUWiJKd1VAst57jq0Hm0TQKi+7yIn0OekO
qeMwS+Bhn9b78uDYOan+pcSo7LagH4yLdwaM44gYiTJgaRnEhwWxcQC6GHdIY3Do
BGEcQzfZfyC17B93uX6+HPesS444RFj/ANK9hDC8vwYIb9a3X3mF/hAaVFlUpvu1
0Ylf5xk/2Hbv5YHe+wfOaVsZ1A==
-----END CERTIFICATE-----
";
            //StringReader reader = new StringReader(cert);
            //PemReader pemReader = new PemReader(reader);
            //var pem = pemReader.ReadPemObject();
            var parser = new X509CertificateParser();
            var cert = parser.ReadCertificate(Encoding.UTF8.GetBytes(pemCert));

            Console.WriteLine("Uploading a certificate to existing CKA ID");
            var dotnetcert = new X509Certificate2(cert.GetEncoded());
            p11.StoreCertificate(session, ckaId, dotnetcert);


            Console.WriteLine("Searching for all certificates");
            var certAttributes = p11.FindAllCertificates(session);

            Console.WriteLine($"Certs Found: {certAttributes.Count}");
            foreach (var certAttr in certAttributes)
            {
                var certFromAttr = new X509Certificate2(certAttr[0].GetValueAsByteArray());
                Console.WriteLine($"Subject from cert: {certFromAttr.Subject}");
                Console.WriteLine($"Thumbprint: {certFromAttr.Thumbprint}");
                Console.WriteLine($"Label: {certAttr[1].GetValueAsString()}");
                Console.WriteLine($"CKA ID: {Encoding.UTF8.GetString(certAttr[2].GetValueAsByteArray())}");
            }

            Console.WriteLine("Finished running pkcs11 ---");
        }
    }
}
