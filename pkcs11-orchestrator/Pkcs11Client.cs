using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace pkcs11_orchestrator
{
    public class Pkcs11Client : IDisposable
    {
        string pkcs11LibraryPath = "";
        private IPkcs11Library _p11;
        private ISession _p11Session;

        public Pkcs11Client(string libPath)
        {
            pkcs11LibraryPath = libPath;

            // Create factories used by Pkcs11Interop library
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            // Load unmanaged PKCS#11 library
            _p11 = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded);
        }

        public ISlot GetOpenSlot()
        {
            var slots = _p11.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
            //return slots.First(slot => !slot.GetSlotInfo().SlotFlags.TokenPresent); // all slots actually have tokens present from start
            return slots.First();
        }

        public ISession LogInToSlot(ISlot slot, string pin)
        {
            _p11Session = slot.OpenSession(SessionType.ReadWrite);
            _p11Session.Login(CKU.CKU_USER, pin);
            return _p11Session;
        }

        public List<List<IObjectAttribute>> FindAllCertificates(ISession session)
        {
            var certAttributesList = new List<List<IObjectAttribute>>();

            var searchAttributes = new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true)
            };

            var certsFound = session.FindAllObjects(searchAttributes);

            foreach (IObjectHandle certObjectHandle in certsFound)
            {
                var certAttributes = session.GetAttributeValue(certObjectHandle, new List<CKA> { CKA.CKA_VALUE, CKA.CKA_LABEL, CKA.CKA_ID });
                certAttributesList.Add(certAttributes);
            }

            return certAttributesList;
        }

        public void PrintSlotContents(ISlot slot)
        {
            ISlotInfo slotInfo = slot.GetSlotInfo();

            Console.WriteLine();
            Console.WriteLine("Slot");
            Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
            Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
            Console.WriteLine("  Token present:      " + slotInfo.SlotFlags.TokenPresent);

            if (slotInfo.SlotFlags.TokenPresent)
            {
                // Show basic information about token present in the slot
                ITokenInfo tokenInfo = slot.GetTokenInfo();

                Console.WriteLine("Token");
                Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                Console.WriteLine("  Model:              " + tokenInfo.Model);
                Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                Console.WriteLine("  Label:              " + tokenInfo.Label);

                // Show list of mechanisms (algorithms) supported by the token
                Console.WriteLine("Supported mechanisms: ");
                foreach (CKM mechanism in slot.GetMechanismList())
                    Console.WriteLine("  " + mechanism);
            }
        }

        public static void GenerateKeyPair(ISession session, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle)
        {
            // The CKA_ID attribute is intended as a means of distinguishing multiple key pairs held by the same subject
            byte[] ckaId = session.GenerateRandom(20);

            // Prepare attribute template of new public key
            List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
            //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "keyfactor"));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
            //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false)); // not supported
            //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 1024));
            publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

            // Prepare attribute template of new private key
            List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "keyfactor"));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
            privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false)); // not supported
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));

            // Specify key generation mechanism
            IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

            // Generate key pair
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
        }

        public string CreateCsr(ISession session, IObjectHandle publicKeyHandle, IObjectHandle privateKeyHandle)
        {
            AsymmetricKeyParameter publicKey = null;
            var subject = new X509Name("CN=pkcs11test&O=Keyfactor");
            var sigAlg = PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id;
            string keytype = "RSA";
            if (keytype == "RSA")
            {
                var keyAttributesToGet = new List<CKA>()
                {
                    CKA.CKA_PUBLIC_EXPONENT,
                    CKA.CKA_MODULUS,
                    CKA.CKA_KEY_TYPE
                };

                var publicKeyAttributes = session.GetAttributeValue(publicKeyHandle, keyAttributesToGet);
                var exponent = new BigInteger(1, publicKeyAttributes[0].GetValueAsByteArray());
                var modulus = new BigInteger(1, publicKeyAttributes[1].GetValueAsByteArray());
                publicKey = new RsaKeyParameters(false, modulus, exponent);
            }
            var csr = new Pkcs10CertificationRequestDelaySigned(sigAlg, subject, publicKey, null);
            var csrSignature = session.Sign(session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS), privateKeyHandle, csr.GetDataToSign());
            csr.SignRequest(csrSignature);
            var formattedCsr = $"-----BEGIN CERTIFICATE REQUEST-----\n{Convert.ToBase64String(csr.GetDerEncoded(), Base64FormattingOptions.InsertLineBreaks)}\n-----END CERTIFICATE REQUEST-----";
            return formattedCsr;
        }

        public IObjectHandle StoreCertificate(ISession session, byte[] ckaId, X509Certificate2 cert)
        {
            // set up CK object with certificate attributes
            List<IObjectAttribute> certificateAttributes = new List<IObjectAttribute>();
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
            //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_CATEGORY, (CKC) CK.CK_CERTIFICATE_CATEGORY_UNSPECIFIED)); // unsure if need to specify category
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "keyfactor"));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId)); // use existing ID of the keypair
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, "CN=pkcs11test&O=Keyfactor")); // TODO: paramterize subject
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, cert.RawData));
            
            return session.CreateObject(certificateAttributes);
        }

        public void RunLoggedOnDiagnostics(string pkcs11LibraryPath, string apiKey)
        {
            // Create factories used by Pkcs11Interop library
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            // Load unmanaged PKCS#11 library
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Show general information about loaded library
                ILibraryInfo libraryInfo = pkcs11Library.GetInfo();

                Console.WriteLine("Library");
                Console.WriteLine("  Manufacturer:       " + libraryInfo.ManufacturerId);
                Console.WriteLine("  Description:        " + libraryInfo.LibraryDescription);
                Console.WriteLine("  Version:            " + libraryInfo.LibraryVersion);

                // Get list of all available slots
                foreach (ISlot slot in pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
                {
                    // log into slot
                    var session = slot.OpenSession(SessionType.ReadWrite);
                    session.Login(CKU.CKU_USER, apiKey);

                    // Show basic information about slot
                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    Console.WriteLine();
                    Console.WriteLine("Slot");
                    Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
                    Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
                    Console.WriteLine("  Token present:      " + slotInfo.SlotFlags.TokenPresent);

                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        // Show basic information about token present in the slot
                        ITokenInfo tokenInfo = slot.GetTokenInfo();

                        Console.WriteLine("Token");
                        Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                        Console.WriteLine("  Model:              " + tokenInfo.Model);
                        Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                        Console.WriteLine("  Label:              " + tokenInfo.Label);

                        // Show list of mechanisms (algorithms) supported by the token
                        Console.WriteLine("Supported mechanisms: ");
                        foreach (CKM mechanism in slot.GetMechanismList())
                            Console.WriteLine("  " + mechanism);
                    }

                    session.Logout();
                    session.CloseSession();
                }
            }
        }

        public void RunGeneralDiagnostics(string pkcs11LibraryPath)
        {

            // Create factories used by Pkcs11Interop library
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            // Load unmanaged PKCS#11 library
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Show general information about loaded library
                ILibraryInfo libraryInfo = pkcs11Library.GetInfo();

                Console.WriteLine("Library");
                Console.WriteLine("  Manufacturer:       " + libraryInfo.ManufacturerId);
                Console.WriteLine("  Description:        " + libraryInfo.LibraryDescription);
                Console.WriteLine("  Version:            " + libraryInfo.LibraryVersion);

                // Get list of all available slots
                foreach (ISlot slot in pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
                {
                    // Show basic information about slot
                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    Console.WriteLine();
                    Console.WriteLine("Slot");
                    Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
                    Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
                    Console.WriteLine("  Token present:      " + slotInfo.SlotFlags.TokenPresent);

                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        // Show basic information about token present in the slot
                        ITokenInfo tokenInfo = slot.GetTokenInfo();

                        Console.WriteLine("Token");
                        Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                        Console.WriteLine("  Model:              " + tokenInfo.Model);
                        Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                        Console.WriteLine("  Label:              " + tokenInfo.Label);

                        // Show list of mechanisms (algorithms) supported by the token
                        Console.WriteLine("Supported mechanisms: ");
                        foreach (CKM mechanism in slot.GetMechanismList())
                            Console.WriteLine("  " + mechanism);
                    }
                }
            }
        }

        public void Dispose()
        {
            try
            {
                // attempt to logout session in case it wasn't logged out and disposed
                _p11Session.Logout();
                _p11Session.Dispose();
            }
            finally
            {
                // unload unmanaged PKCS11 library
                _p11.Dispose();
            }
        }
    }
}
