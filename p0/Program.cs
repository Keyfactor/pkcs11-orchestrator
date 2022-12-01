using Net.Pkcs11Interop.HighLevelAPI;
using pkcs11_orchestrator;
using System;

namespace p0
{
    class Program
    {
        static void Main(string[] args)
        {
            string apiKey = "ZjkzNTk0OGItYjUxZS00NjdiLWI4Y2QtMGJkZGVmNTY0ZWVjOnFMQVdJLV9JY2x1eFh4RkJiekdQMDJja0tQMFJQRnRULW50bmJWb09QLWFmaXR5N2ZVSW5uMnVJam14dnVPa2ZLcG9sLUtTTXNGNG95ekI0Ujhwcld3";
            Console.WriteLine("Test running pkcs11 ---");
            var p11 = new Pkcs11Client(@"C:\Program Files\Fortanix\KmsClient\FortanixKmsPkcs11.dll");
            var slot = p11.GetOpenSlot();
            p11.PrintSlotContents(slot);
            var session = p11.LogInToSlot(slot, apiKey);
            IObjectHandle pubKey, privKey;
            Pkcs11Client.GenerateKeyPair(session, out pubKey, out privKey);
            var csr = p11.CreateCsr(session, pubKey, privKey);
            Console.WriteLine("Generated CSR with keys in HSM:");
            Console.WriteLine(csr);
            Console.WriteLine("Finished running pkcs11 ---");
        }
    }
}
