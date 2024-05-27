using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;

namespace SharpSAMDump
{
    internal class Privileges
    {
        public const string SeBackupPrivilege = "SeBackupPrivilege";

        public static void EnablePrivilege(string name, bool enabled = true)
        {
            SafeFileHandle hToken = GetCurrentProcessToken(TOKEN_ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | TOKEN_ACCESS_MASK.TOKEN_QUERY);
            LUID luid = LookupPrivilegeLUID(name);

            LUID_AND_ATTRIBUTES privileges = new LUID_AND_ATTRIBUTES()
            {
                Luid = luid,
                Attributes = enabled ? TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED : 0,
            };

            TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES();
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges.e0 = privileges;

            unsafe
            {
                if (!PInvoke.AdjustTokenPrivileges(hToken, false, &tokenPrivileges, 0, null, null))
                {
                    throw new Win32Exception();
                }
            }
        }

        public static bool IsPrivilegeEnabled(string name)
        {
            bool retval = false;

            SafeFileHandle hToken = GetCurrentProcessToken(TOKEN_ACCESS_MASK.TOKEN_QUERY);
            LUID luid = LookupPrivilegeLUID(name);

            unsafe
            {
                uint returnLength;
                if (!PInvoke.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, null, 0, out returnLength))
                {
                    if ((WIN32_ERROR)Marshal.GetLastWin32Error() != WIN32_ERROR.ERROR_INSUFFICIENT_BUFFER)
                    {
                        throw new Win32Exception();
                    }
                }

                IntPtr tokenInformation = Marshal.AllocHGlobal((int)returnLength);

                if (!PInvoke.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, tokenInformation.ToPointer(), returnLength, out returnLength))
                {
                    Marshal.FreeHGlobal(tokenInformation);
                    throw new Win32Exception();
                }

                TOKEN_PRIVILEGES tokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_PRIVILEGES));                   
                for (int index = 0; index < tokenPrivileges.PrivilegeCount; index++)
                {
                    LUID_AND_ATTRIBUTES privilege = tokenPrivileges.Privileges[index];
                    if (privilege.Luid.Equals(luid) && (privilege.Attributes & TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0)
                    {
                        retval = true;
                        break;
                    }
                }

                Marshal.FreeHGlobal(tokenInformation);
            }

            return retval;
        }

        private static SafeFileHandle GetCurrentProcessToken(TOKEN_ACCESS_MASK accessMask)
        {
            SafeFileHandle hProcess = PInvoke.GetCurrentProcess_SafeHandle();

            SafeFileHandle hToken;
            if (!PInvoke.OpenProcessToken(hProcess, accessMask, out hToken))
            {
                throw new Win32Exception();
            }

            return hToken;
        }

        private static LUID LookupPrivilegeLUID(string name)
        {
            LUID luid;
            if (!PInvoke.LookupPrivilegeValue(null, name, out luid))
            {
                throw new Win32Exception();
            }
            return luid;
        }

        private static string LookupPrivilegeName(LUID luid)
        {

            string privilegeName = "";
            uint bufferSize = 256;

            unsafe
            {
                fixed (char* buffer = new char[bufferSize])
                {
                    PInvoke.LookupPrivilegeName(null, luid, buffer, ref bufferSize);
                    privilegeName = new string(buffer);
                }
            }

            return privilegeName;
        }
    }
}
