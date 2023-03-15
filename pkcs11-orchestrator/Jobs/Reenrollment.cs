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

using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Net.Pkcs11Interop.HighLevelAPI;

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
                p11.GenerateKeyPair(session, label, keyType, out pubKeyHandle, out privKeyHandle, out ckaId);
                logger.LogInformation("New keypair generated on PKCS11 device.");

                logger.LogDebug("Creating CSR...");
                string csr = p11.CreateCsr(session, subject, keyType, pubKeyHandle, privKeyHandle);

                logger.LogDebug("Submitting CSR to Keyfactor");
                var cert = submitReenrollmentUpdate.Invoke(csr);
                logger.LogTrace("Certificate returned from CSR enrollment.");

                logger.LogDebug("Storing enrolled certificate on PKCS11 device.");
                p11.StoreCertificate(session, label, subject, ckaId, cert);
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
