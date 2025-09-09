using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace WindowsCredentialManagerAPI
{
    /// <summary>
    /// Provides access to the Windows Credential Manager for storing and retrieving credentials securely
    /// </summary>
    public static class WindowsCredentialManager
    {
        #region Win32 API Declarations

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDelete(string target, int type, int reservedFlag);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredEnumerate(string? filter, int flag, out int count, out IntPtr pCredentials);

        [DllImport("advapi32.dll")]
        private static extern void CredFree([In] IntPtr buffer);

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// Securely clears a byte array by overwriting with zeros
        /// </summary>
        /// <param name="data">The byte array to clear</param>
        private static void SecureClearBytes(byte[]? data)
        {
            if (data != null)
            {
                Array.Clear(data, 0, data.Length);
            }
        }

        /// <summary>
        /// Converts a SecureString to a byte array
        /// </summary>
        /// <param name="secureString">The SecureString to convert</param>
        /// <returns>A byte array containing the SecureString data</returns>
        private static byte[] SecureStringToBytes(SecureString secureString)
        {
            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                int length = secureString.Length * 2; // Unicode is 2 bytes per character
                byte[] bytes = new byte[length];
                Marshal.Copy(unmanagedString, bytes, 0, length);
                return bytes;
            }
            finally
            {
                if (unmanagedString != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
                }
            }
        }

        /// <summary>
        /// Converts a byte array to a SecureString
        /// </summary>
        /// <param name="bytes">The byte array to convert</param>
        /// <returns>A SecureString containing the data</returns>
        private static SecureString BytesToSecureString(byte[] bytes)
        {
            if (bytes.Length % 2 != 0)
                throw new ArgumentException("Byte array length must be even for Unicode conversion");

            char[] chars = new char[bytes.Length / 2];
            Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);

            SecureString secureString = new SecureString();
            try
            {
                foreach (char c in chars)
                {
                    secureString.AppendChar(c);
                }
                secureString.MakeReadOnly();
                return secureString;
            }
            finally
            {
                Array.Clear(chars, 0, chars.Length);
            }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Saves a credential to the Windows Credential Manager
        /// </summary>
        /// <param name="target">The target name for the credential</param>
        /// <param name="username">The username</param>
        /// <param name="password">The password</param>
        /// <param name="type">The credential type (default: Generic)</param>
        /// <param name="persistence">The persistence level (default: LocalMachine)</param>
        /// <returns>True if successful, false otherwise</returns>
        /// <exception cref="ArgumentException">Thrown when target or username is null or empty</exception>
        /// <exception cref="ArgumentNullException">Thrown when password is null</exception>
        public static bool SaveCredential(string target, string username, string password, 
            CredentialType type = CredentialType.Generic, 
            CredentialPersistence persistence = CredentialPersistence.LocalMachine)
        {
            if (string.IsNullOrEmpty(target))
                throw new ArgumentException("Target cannot be null or empty", nameof(target));
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be null or empty", nameof(username));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            byte[] passwordBytes = Encoding.Unicode.GetBytes(password);

            CREDENTIAL credential = new CREDENTIAL
            {
                AttributeCount = 0,
                Attributes = IntPtr.Zero,
                Comment = IntPtr.Zero,
                TargetAlias = IntPtr.Zero,
                Type = (int)type,
                Persist = (int)persistence,
                CredentialBlobSize = passwordBytes.Length,
                TargetName = Marshal.StringToCoTaskMemUni(target),
                CredentialBlob = Marshal.AllocCoTaskMem(passwordBytes.Length),
                UserName = Marshal.StringToCoTaskMemUni(username)
            };

            try
            {
                Marshal.Copy(passwordBytes, 0, credential.CredentialBlob, passwordBytes.Length);
                return CredWrite(ref credential, 0);
            }
            finally
            {
                SecureClearBytes(passwordBytes);
                Marshal.FreeCoTaskMem(credential.TargetName);
                Marshal.FreeCoTaskMem(credential.CredentialBlob);
                Marshal.FreeCoTaskMem(credential.UserName);
            }
        }

        /// <summary>
        /// Saves a credential to the Windows Credential Manager using SecureString
        /// </summary>
        /// <param name="target">The target name for the credential</param>
        /// <param name="username">The username</param>
        /// <param name="securePassword">The password as SecureString</param>
        /// <param name="type">The credential type (default: Generic)</param>
        /// <param name="persistence">The persistence level (default: LocalMachine)</param>
        /// <returns>True if successful, false otherwise</returns>
        /// <exception cref="ArgumentException">Thrown when target or username is null or empty</exception>
        /// <exception cref="ArgumentNullException">Thrown when securePassword is null</exception>
        public static bool SaveCredential(string target, string username, SecureString securePassword,
            CredentialType type = CredentialType.Generic,
            CredentialPersistence persistence = CredentialPersistence.LocalMachine)
        {
            if (string.IsNullOrEmpty(target))
                throw new ArgumentException("Target cannot be null or empty", nameof(target));
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be null or empty", nameof(username));
            if (securePassword == null)
                throw new ArgumentNullException(nameof(securePassword));

            byte[] passwordBytes = SecureStringToBytes(securePassword);

            CREDENTIAL credential = new CREDENTIAL
            {
                AttributeCount = 0,
                Attributes = IntPtr.Zero,
                Comment = IntPtr.Zero,
                TargetAlias = IntPtr.Zero,
                Type = (int)type,
                Persist = (int)persistence,
                CredentialBlobSize = passwordBytes.Length,
                TargetName = Marshal.StringToCoTaskMemUni(target),
                CredentialBlob = Marshal.AllocCoTaskMem(passwordBytes.Length),
                UserName = Marshal.StringToCoTaskMemUni(username)
            };

            try
            {
                Marshal.Copy(passwordBytes, 0, credential.CredentialBlob, passwordBytes.Length);
                return CredWrite(ref credential, 0);
            }
            finally
            {
                SecureClearBytes(passwordBytes);
                Marshal.FreeCoTaskMem(credential.TargetName);
                Marshal.FreeCoTaskMem(credential.CredentialBlob);
                Marshal.FreeCoTaskMem(credential.UserName);
            }
        }

        /// <summary>
        /// Retrieves a credential from the Windows Credential Manager
        /// </summary>
        /// <param name="target">The target name of the credential</param>
        /// <param name="type">The credential type (default: Generic)</param>
        /// <returns>A NetworkCredential object if found, null otherwise</returns>
        /// <exception cref="ArgumentException">Thrown when target is null or empty</exception>
        public static NetworkCredential? GetCredential(string target, CredentialType type = CredentialType.Generic)
        {
            if (string.IsNullOrEmpty(target))
                throw new ArgumentException("Target cannot be null or empty", nameof(target));

            IntPtr credPtr;
            if (!CredRead(target, (int)type, 0, out credPtr))
            {
                return null;
            }

            try
            {
                CREDENTIAL cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);
                string username = Marshal.PtrToStringUni(cred.UserName) ?? string.Empty;
                string password = string.Empty;

                if (cred.CredentialBlob != IntPtr.Zero && cred.CredentialBlobSize > 0)
                {
                    byte[] passwordBytes = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, cred.CredentialBlobSize);
                    password = Encoding.Unicode.GetString(passwordBytes);
                    SecureClearBytes(passwordBytes);
                }

                return new NetworkCredential(username, password);
            }
            finally
            {
                CredFree(credPtr);
            }
        }

        /// <summary>
        /// Retrieves a credential from the Windows Credential Manager as SecureString
        /// </summary>
        /// <param name="target">The target name of the credential</param>
        /// <param name="type">The credential type (default: Generic)</param>
        /// <returns>A SecureNetworkCredential object if found, null otherwise</returns>
        /// <exception cref="ArgumentException">Thrown when target is null or empty</exception>
        public static SecureNetworkCredential? GetSecureCredential(string target, CredentialType type = CredentialType.Generic)
        {
            if (string.IsNullOrEmpty(target))
                throw new ArgumentException("Target cannot be null or empty", nameof(target));

            IntPtr credPtr;
            if (!CredRead(target, (int)type, 0, out credPtr))
            {
                return null;
            }

            try
            {
                CREDENTIAL cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);
                string username = Marshal.PtrToStringUni(cred.UserName) ?? string.Empty;
                SecureString? securePassword = null;

                if (cred.CredentialBlob != IntPtr.Zero && cred.CredentialBlobSize > 0)
                {
                    byte[] passwordBytes = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, cred.CredentialBlobSize);
                    try
                    {
                        securePassword = BytesToSecureString(passwordBytes);
                    }
                    finally
                    {
                        SecureClearBytes(passwordBytes);
                    }
                }

                return new SecureNetworkCredential(username, securePassword ?? new SecureString());
            }
            finally
            {
                CredFree(credPtr);
            }
        }

        /// <summary>
        /// Deletes a credential from the Windows Credential Manager
        /// </summary>
        /// <param name="target">The target name of the credential</param>
        /// <param name="type">The credential type (default: Generic)</param>
        /// <returns>True if successful, false otherwise</returns>
        /// <exception cref="ArgumentException">Thrown when target is null or empty</exception>
        public static bool DeleteCredential(string target, CredentialType type = CredentialType.Generic)
        {
            if (string.IsNullOrEmpty(target))
                throw new ArgumentException("Target cannot be null or empty", nameof(target));

            return CredDelete(target, (int)type, 0);
        }

        /// <summary>
        /// Enumerates all credentials in the Windows Credential Manager
        /// </summary>
        /// <param name="filter">Optional filter for credential names</param>
        /// <returns>A list of credential information</returns>
        /// <exception cref="Win32Exception">Thrown when enumeration fails</exception>
        public static List<CredentialInfo> EnumerateCredentials(string? filter = null)
        {
            List<CredentialInfo> credentials = new List<CredentialInfo>();
            IntPtr pCredentials;
            int count;

            if (!CredEnumerate(filter, 0, out count, out pCredentials))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 1168) // ERROR_NOT_FOUND
                    return credentials;
                
                throw new Win32Exception(error);
            }
            try
            {
                IntPtr[] credentialPtrs = new IntPtr[count];
                Marshal.Copy(pCredentials, credentialPtrs, 0, count);

                for (int i = 0; i < count; i++)
                {
                    CREDENTIAL cred = Marshal.PtrToStructure<CREDENTIAL>(credentialPtrs[i]);
                    
                    string target = Marshal.PtrToStringUni(cred.TargetName) ?? string.Empty;
                    string username = Marshal.PtrToStringUni(cred.UserName) ?? string.Empty;
                    string comment = Marshal.PtrToStringUni(cred.Comment) ?? string.Empty;

                    credentials.Add(new CredentialInfo
                    {
                        Target = target,
                        Username = username,
                        Comment = comment,
                        Type = (CredentialType)cred.Type,
                        Persistence = (CredentialPersistence)cred.Persist
                    });
                }
            }
            finally
            {
                CredFree(pCredentials);
            }

            return credentials;
        }

        /// <summary>
        /// Checks if a credential exists in the Windows Credential Manager
        /// </summary>
        /// <param name="target">The target name of the credential</param>
        /// <param name="type">The credential type (default: Generic)</param>
        /// <returns>True if the credential exists, false otherwise</returns>
        /// <exception cref="ArgumentException">Thrown when target is null or empty</exception>
        public static bool CredentialExists(string target, CredentialType type = CredentialType.Generic)
        {
            if (string.IsNullOrEmpty(target))
                throw new ArgumentException("Target cannot be null or empty", nameof(target));

            IntPtr credPtr;
            if (CredRead(target, (int)type, 0, out credPtr))
            {
                CredFree(credPtr);
                return true;
            }
            return false;
        }

        #endregion
    }

    #region Supporting Classes and Enums

    /// <summary>
    /// Represents credential information
    /// </summary>
    public class CredentialInfo
    {
        /// <summary>
        /// The target name of the credential
        /// </summary>
        public string Target { get; set; } = string.Empty;

        /// <summary>
        /// The username associated with the credential
        /// </summary>
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Optional comment for the credential
        /// </summary>
        public string Comment { get; set; } = string.Empty;

        /// <summary>
        /// The type of the credential
        /// </summary>
        public CredentialType Type { get; set; }

        /// <summary>
        /// The persistence level of the credential
        /// </summary>
        public CredentialPersistence Persistence { get; set; }
    }

    /// <summary>
    /// Represents a network credential with username and password
    /// </summary>
    public class NetworkCredential
    {
        /// <summary>
        /// The username
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// The password
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Initializes a new instance of NetworkCredential
        /// </summary>
        /// <param name="username">The username</param>
        /// <param name="password">The password</param>
        public NetworkCredential(string username, string password)
        {
            Username = username ?? string.Empty;
            Password = password ?? string.Empty;
        }
    }

    /// <summary>
    /// Represents a network credential with username and secure password
    /// </summary>
    public class SecureNetworkCredential : IDisposable
    {
        /// <summary>
        /// The username
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// The password as SecureString
        /// </summary>
        public SecureString Password { get; set; }

        /// <summary>
        /// Initializes a new instance of SecureNetworkCredential
        /// </summary>
        /// <param name="username">The username</param>
        /// <param name="password">The password as SecureString</param>
        public SecureNetworkCredential(string username, SecureString password)
        {
            Username = username ?? string.Empty;
            Password = password ?? new SecureString();
        }

        /// <summary>
        /// Disposes the SecureString password
        /// </summary>
        public void Dispose()
        {
            Password?.Dispose();
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// Credential types supported by Windows Credential Manager
    /// </summary>
    public enum CredentialType
    {
        /// <summary>
        /// Generic credential type
        /// </summary>
        Generic = 1,

        /// <summary>
        /// Domain password credential
        /// </summary>
        DomainPassword = 2,

        /// <summary>
        /// Domain certificate credential
        /// </summary>
        DomainCertificate = 3,

        /// <summary>
        /// Domain visible password credential
        /// </summary>
        DomainVisiblePassword = 4,

        /// <summary>
        /// Generic certificate credential
        /// </summary>
        GenericCertificate = 5,

        /// <summary>
        /// Domain extended credential
        /// </summary>
        DomainExtended = 6,

        /// <summary>
        /// Maximum credential type value
        /// </summary>
        Maximum = 7,

        /// <summary>
        /// Extended maximum credential type value
        /// </summary>
        MaximumEx = 1007
    }

    /// <summary>
    /// Credential persistence options
    /// </summary>
    public enum CredentialPersistence
    {
        /// <summary>
        /// Credential persists for the current session only
        /// </summary>
        Session = 1,

        /// <summary>
        /// Credential persists on the local machine
        /// </summary>
        LocalMachine = 2,

        /// <summary>
        /// Credential persists across the enterprise
        /// </summary>
        Enterprise = 3
    }

    #endregion
}