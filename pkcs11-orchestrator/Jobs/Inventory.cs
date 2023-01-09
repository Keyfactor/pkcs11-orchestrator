using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Keyfactor.Orchestrator.Extensions.Pkcs11.Jobs
{
    public class Inventory : IInventoryJobExtension
    {
        public string ExtensionName => "PKCS11";

        public JobResult ProcessJob(InventoryJobConfiguration jobConfiguration, SubmitInventoryUpdate submitInventoryUpdate)
        {
            ILogger logger = LogHandler.GetClassLogger<Inventory>();
            string pkcs11LibraryPath = jobConfiguration.CertificateStoreDetails.StorePath;
            string userPin = jobConfiguration.CertificateStoreDetails.StorePassword;

            logger.LogDebug($"Attempting to load PKCS11 Library at {pkcs11LibraryPath}");
            Pkcs11Client p11 = new Pkcs11Client(pkcs11LibraryPath);
            logger.LogTrace("PKCS11 Library loaded.");

            List<CurrentInventoryItem> inventory = new List<CurrentInventoryItem>();
            using (p11)
            {
                logger.LogDebug("Getting open PKCS11 slot...");
                ISlot slot = p11.GetOpenSlot();
                logger.LogTrace($"Slot found with Slot ID {slot.SlotId}");

                logger.LogDebug("Logging in to slot...");
                ISession session = p11.LogInToSlot(slot, userPin);
                logger.LogTrace($"Logged in to slot with Session ID {session.SessionId}");

                logger.LogDebug("Searching for certificates...");
                var certAttributes = p11.FindAllCertificates(session);
                logger.LogTrace($"Found {certAttributes.Count} sets of certificate attributes.");

                logger.LogDebug("Reading certificate information for inventory result...");
                foreach(List<IObjectAttribute> certAttr in certAttributes)
                {
                    byte[] certData = certAttr[0].GetValueAsByteArray();
                    string label = certAttr[1].GetValueAsString();
                    byte[] ckaId = certAttr[2].GetValueAsByteArray();

                    var x509Cert = new X509Certificate2(certData);

                    inventory.Add(new CurrentInventoryItem()
                    {
                        Certificates = new string[] { Convert.ToBase64String(x509Cert.Export(X509ContentType.Cert)) },
                        Alias = label,
                        PrivateKeyEntry = p11.CertificateHasPrivateKey(session, ckaId, label),
                        UseChainLevel = false
                    });
                }
            }

            logger.LogInformation($"Found {inventory.Count} certificates.");
            bool success = submitInventoryUpdate.Invoke(inventory);
            logger.LogTrace("Inventory resulst submitted to Keyfactor.");

            JobResult result = new JobResult()
            {
                JobHistoryId = jobConfiguration.JobHistoryId,
                Result = success ? Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Success : Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Failure
            };
            return result;
        }
    }
}
