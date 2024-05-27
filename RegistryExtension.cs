using Microsoft.Win32.SafeHandles;
using Microsoft.Win32;
using System.ComponentModel;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Registry;

namespace SharpSAMDump
{
    public static class RegistryExtension
    {
        public static RegistryKey OpenSubKeyForBackup(this RegistryKey key, string name)
        {
            SafeRegistryHandle hRegistry;

            unsafe
            {
                WIN32_ERROR error = PInvoke.RegOpenKeyEx(
                    key.Handle,
                    name,
                    (uint)REG_OPEN_CREATE_OPTIONS.REG_OPTION_BACKUP_RESTORE,
                    REG_SAM_FLAGS.KEY_READ,
                    out hRegistry);

                if (error != WIN32_ERROR.NO_ERROR)
                {
                    throw new Win32Exception((int)error);
                }
            }

            return RegistryKey.FromHandle(hRegistry);
        }

        public static int GetValueKindInt(this RegistryKey key, string name)
        {
            int kind = 0;

            unsafe
            {
                WIN32_ERROR error = PInvoke.RegQueryValueEx(
                    key.Handle,
                    name,
                    (REG_VALUE_TYPE*)&kind,
                    null,
                    null
                );
                if (error != WIN32_ERROR.ERROR_SUCCESS)
                {
                    throw new Win32Exception((int)error);
                }
            }

            return kind;
        }

        public static string GetClassName(this RegistryKey key)
        {
            string className = "";
            
            unsafe
            { 
                uint bufferSize = 256;
                fixed (char* buffer = new char[bufferSize])
                {
                    PInvoke.RegQueryInfoKey(key.Handle, buffer, &bufferSize, null, null, null, null, null, null, null, null);
                    className = new string(buffer);
                }
            }

            return className;
        }
    }
}
