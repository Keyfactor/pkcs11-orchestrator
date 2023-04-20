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
            logger.LogTrace("Inventory results submitted to Keyfactor.");

            JobResult result = new JobResult()
            {
                JobHistoryId = jobConfiguration.JobHistoryId,
                Result = success ? Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Success : Orchestrators.Common.Enums.OrchestratorJobStatusJobResult.Failure
            };
            return result;
        }
    }
}
