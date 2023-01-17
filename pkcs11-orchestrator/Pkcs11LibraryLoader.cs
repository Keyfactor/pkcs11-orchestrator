using Microsoft.Extensions.Logging;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Collections.Generic;

namespace Keyfactor.Orchestrator.Extensions.Pkcs11
{
    public static class Pkcs11LibraryLoader
    {
        private static Dictionary<string, IPkcs11Library> _p11Libraries;

        public static IPkcs11Library LoadPkcs11Library(string libPath, ILogger logger)
        {
            if (_p11Libraries == null)
            {
                logger.LogTrace("PKCS11 Library list does not exist, initializing.");
                _p11Libraries = new Dictionary<string, IPkcs11Library>();
            }

            // Load PKCS#11 library
            if (_p11Libraries.ContainsKey(libPath))
            {
                // library already loaded, use existing static instance
                logger.LogTrace($"PKCS11 Library is already loaded. Using library located at {libPath}");
                return _p11Libraries[libPath];
            }
            else
            {
                // library is not loaded, create new static instance and store for later use
                logger.LogTrace("No loaded PKCS11 library found, loading new PKCS11 library instance");
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                IPkcs11Library p11 = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libPath, AppType.SingleThreaded);
                _p11Libraries.Add(libPath, p11);
                logger.LogDebug($"New PKCS11 library instance loaded from {libPath}");
                return p11;
            }
        }
    }
}
