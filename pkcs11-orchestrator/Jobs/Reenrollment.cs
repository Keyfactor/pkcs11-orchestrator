using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Text;

namespace Keyfactor.Orchestrator.Extensions.Pkcs11.Jobs
{
    public class Reenrollment : IReenrollmentJobExtension
    {
        public string ExtensionName => "PKCS11";

        public JobResult ProcessJob(ReenrollmentJobConfiguration jobConfiguration, SubmitReenrollmentCSR submitReenrollmentUpdate)
        {
            ILogger logger = LogHandler.GetClassLogger<Reenrollment>();
            string pkcs11LibraryPath = jobConfiguration.CertificateStoreDetails.StorePath;
            string userPin = jobConfiguration.CertificateStoreDetails.StorePassword;

            var allJobProps = jobConfiguration.JobProperties;
            string subject = allJobProps["subjectText"].ToString();
            string keyType = allJobProps["keyType"].ToString();
            string label = allJobProps["label"].ToString();

            logger.LogDebug($"Attempting to load PKCS11 Library at {pkcs11LibraryPath}");
            Pkcs11Client p11 = new Pkcs11Client(pkcs11LibraryPath);
            logger.LogTrace("PKCS11 Library loaded.");

            using (p11)
            {
                logger.LogDebug("Getting open PKCS11 slot...");
                ISlot slot = p11.GetOpenSlot();
                logger.LogTrace($"Slot found with Slot ID {slot.SlotId}");

                logger.LogDebug("Logging in to slot...");
                ISession session = p11.LogInToSlot(slot, userPin);
                logger.LogTrace($"Logged in to slot with Session ID {session.SessionId}");

                IObjectHandle pubKeyHandle, privKeyHandle;
                byte[] ckaId;
                logger.LogDebug("Attempting to generate new keypair.");
                p11.GenerateKeyPair(session, label, out pubKeyHandle, out privKeyHandle, out ckaId);
                logger.LogInformation("New keypair generated on PKCS11 device.");

                logger.LogDebug("Creating CSR...");
                string csr = p11.CreateCsr(session, subject, pubKeyHandle, privKeyHandle);

                logger.LogDebug("Submitting CSR to Keyfactor");
                var cert = submitReenrollmentUpdate.Invoke(csr);
                logger.LogTrace("Certificate returned from CSR enrollment.");

                logger.LogDebug("Storing enrolled certificate on PKCS11 device.");
                p11.StoreCertificate(session, ckaId, cert);
                logger.LogTrace("Certificate stored successfully.");
            }

            JobResult result = new JobResult()
            {
                JobHistoryId = jobConfiguration.JobHistoryId,
                Result = Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Success
            };
            return result;
        }
    }
}
