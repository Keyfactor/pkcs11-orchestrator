// Copyright 2023 Keyfactor
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
using Microsoft.Extensions.Logging;
using Keyfactor.Logging;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math.EC;

namespace Keyfactor.Orchestrator.Extensions.Pkcs11
{
    public class Pkcs11Client : IDisposable
    {
        private IPkcs11Library _p11 = null;
        private ISession _p11Session;
        private ILogger _logger;

        public Pkcs11Client(string libPath)
        {
            _logger = LogHandler.GetClassLogger<Pkcs11Client>();

            _logger.LogTrace($"Loading PKCS11 library at {libPath}");
            _p11 = Pkcs11LibraryLoader.LoadPkcs11Library(libPath, _logger);
        }

        public ISlot GetOpenSlot()
        {
            var slots = _p11.GetSlotList(SlotsType.WithTokenPresent);
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

        public bool CertificateHasPrivateKey(ISession session, byte[] ckaId, string label)
        {
            var searchAttributes = new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label)
            };

            var privKeyFound = session.FindAllObjects(searchAttributes);

            return privKeyFound.Count == 1;
        }

        public void GenerateKeyPair(ISession session, string alias, string keyType, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle, out byte[] outCkaId)
        {
            // The CKA_ID attribute is supposed to be the same for a keypair and matching certificate
            byte[] ckaId = session.GenerateRandom(20);

            List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
            List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
            IMechanism mechanism;
            if (keyType == "RSA")
            {
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, alias));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, alias));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));

                mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
            }
            else
            {
                // get curve parameter
                X962Parameters x962Parameters = new X962Parameters(NistNamedCurves.GetByName("P-256"));
                byte[] ecParams = x962Parameters.GetDerEncoded();

                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, alias));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
                publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, ecParams));

                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, alias));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
                privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));

                mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_EC_KEY_PAIR_GEN);
            }

            // Generate key pair
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
            outCkaId = ckaId;
        }

        public string CreateCsr(ISession session, string subjectIn, string keyType, IObjectHandle publicKeyHandle, IObjectHandle privateKeyHandle)
        {
            AsymmetricKeyParameter publicKey = null;
            var subject = new X509Name(subjectIn);
            string sigAlg;
            IMechanism mechanism;

            if (keyType == "RSA")
            {
                sigAlg = PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id;
                mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);

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
            else
            {
                sigAlg = "SHA256withECDSA";
                mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA_SHA256);

                var keyAttributesToGet = new List<CKA>()
                {
                    CKA.CKA_EC_POINT,
                    CKA.CKA_EC_PARAMS,
                    CKA.CKA_KEY_TYPE
                };

                var publicKeyAttributes = session.GetAttributeValue(publicKeyHandle, keyAttributesToGet);

                X9ECParameters curveParams = ECNamedCurveTable.GetByName("P-256");
                ECCurve curve = curveParams.Curve;
                ECDomainParameters domainParams = new ECDomainParameters(curve, curveParams.G, curveParams.N, curveParams.H);
                ECPoint point = curve.DecodePoint(publicKeyAttributes[0].GetValueAsByteArray());

                publicKey = new ECPublicKeyParameters(point, domainParams);
            }

            var csr = new Pkcs10CertificationRequestDelaySigned(sigAlg, subject, publicKey, null);
            var csrSignature = session.Sign(mechanism, privateKeyHandle, csr.GetDataToSign());
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
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "keyfactor"));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId)); // use existing ID of the keypair
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, "CN=pkcs11test&O=Keyfactor")); // TODO: paramterize subject
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, cert.RawData));
            
            return session.CreateObject(certificateAttributes);
        }

        public void Dispose()
        {
            try
            {
                // attempt to logout session in case it wasn't logged out and disposed
                _p11Session.Logout();
                _p11Session.Dispose();
            }
            catch
            {
                _logger.LogDebug("PKCS11 Session was already logged out or disposed.");
            }
        }
    }
}
