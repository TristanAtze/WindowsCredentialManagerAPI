using System.Runtime.InteropServices;
using System.Security;

public static partial class WindowsCredentialManager
{
    // --- P/Invoke Deklarationen für Credential Manager API ---

    private const string CredmgrDll = "advapi32.dll";

    // Gemacht internal, da nur intern von dieser Klasse oder anderen in derselben Assembly benötigt
    internal enum CREDENTIAL_TYPE : uint
    {
        GENERIC = 1,
    }

    // Fix for CS0051: Make the CRED_PERSIST enum public to match the accessibility of the SavePassword method.
    public enum CRED_PERSIST : uint
    {
        SESSION = 1,
        LOCAL_MACHINE = 2,
        ENTERPRISE = 3,
    }

    // Gemacht internal
    [StructLayout(LayoutKind.Sequential)]
    internal struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    // Gemacht internal
    [StructLayout(LayoutKind.Sequential)]
    internal struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName; // LPWSTR
        public IntPtr Comment; // LPWSTR
        public FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob; // BYTE *
        public uint Persist; // CRED_PERSIST
        public uint AttributeCount;
        public IntPtr Attributes; // PCREDENTIAL_ATTRIBUTE
        public IntPtr AcquireCredentialsHandle;
        public IntPtr AcquireCredentialsHandleArgs;
    }

    [LibraryImport(CredmgrDll, EntryPoint = "CredReadW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)] // Gibt Bool zurück
    internal static partial bool CredRead(
        string TargetName,
        CREDENTIAL_TYPE Type,
        int Flags,
        out IntPtr Credential // Wird von API zugewiesen
    );

    [DllImport(CredmgrDll, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredWrite(
        ref CREDENTIAL Credential,
        int Flags
    );

    [DllImport(CredmgrDll, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CredDelete(
        string TargetName,
        CREDENTIAL_TYPE Type,
        int Flags
    );

    [DllImport(CredmgrDll, EntryPoint = "CredFree", SetLastError = true)]
    internal static extern void CredFree(IntPtr Credential);

    // --- Hilfsfunktion zum Konvertieren und Löschen von SecureString ---
    // Nutzt die ClearBytes Methode aus HighlySecureAuthenticatedVersionedCipher
    private static byte[]? SecureStringToBytes(SecureString secureString)
    {
        if (secureString == null) return null;

        IntPtr unmanagedBytes = IntPtr.Zero;
        IntPtr managedBytesPtr = IntPtr.Zero; // Für das Byte-Array, das wir manuell erstellen

        try
        {
            // Marshal.SecureStringToGlobalAllocUnicode kopiert SecureString sicher
            // in unmanaged Speicher und gibt einen Pointer zurück.
            unmanagedBytes = Marshal.SecureStringToGlobalAllocUnicode(secureString);

            // Die Länge ist die Anzahl der Zeichen * 2 (für UTF16/Unicode).
            int byteLength = secureString.Length * 2;

            // Erstelle ein managed Byte-Array und kopiere die Daten hinein.
            byte[] bytes = new byte[byteLength];
            Marshal.Copy(unmanagedBytes, bytes, 0, byteLength);

            // Gib das managed Byte-Array zurück. Der AUFRUFER muss es löschen!
            return bytes;
        }
        finally
        {
            // Lösche den unmanaged Speicher sicher
            if (unmanagedBytes != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocAnsi(unmanagedBytes);
            }
        }
    }

    public static bool SavePassword(string targetName, SecureString password, CRED_PERSIST persistType = CRED_PERSIST.LOCAL_MACHINE, string? comment = null)
    {
        if (string.IsNullOrEmpty(targetName)) throw new ArgumentNullException(nameof(targetName));
        if (password == null) throw new ArgumentNullException(nameof(password));

        byte[]? passwordBytes = null; // Managed copy
        IntPtr targetNamePtr = IntPtr.Zero;
        IntPtr commentPtr = IntPtr.Zero;
        GCHandle passwordBytesHandle = default;

        try
        {
            passwordBytes = SecureStringToBytes(password) ?? [];
            if (passwordBytes == null) return false;

            passwordBytesHandle = GCHandle.Alloc(passwordBytes, GCHandleType.Pinned);
            IntPtr credentialBlobPtr = passwordBytesHandle.AddrOfPinnedObject();

            targetNamePtr = Marshal.StringToHGlobalUni(targetName);
            if (comment != null)
            {
                commentPtr = Marshal.StringToHGlobalUni(comment);
            }

            CREDENTIAL cred = new()
            {
                Flags = 0,
                Type = (uint)CREDENTIAL_TYPE.GENERIC,
                TargetName = targetNamePtr,
                Comment = commentPtr,
                CredentialBlobSize = (uint)passwordBytes.Length,
                CredentialBlob = credentialBlobPtr,
                Persist = (uint)persistType,
                AttributeCount = 0,
                Attributes = IntPtr.Zero,
                AcquireCredentialsHandle = IntPtr.Zero,
                AcquireCredentialsHandleArgs = IntPtr.Zero
            };

            bool success = CredWrite(ref cred, 0);

            if (!success)
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"Error writing credential: {error} (Win32 Error)");
            }

            return success;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception saving credential: {ex.Message}");
            return false;
        }
        finally
        {
            HighlySecureAuthenticatedVersionedCipher.ClearBytes(passwordBytes);
            if (passwordBytesHandle.IsAllocated) passwordBytesHandle.Free();

            if (targetNamePtr != IntPtr.Zero) Marshal.FreeHGlobal(targetNamePtr);
            if (commentPtr != IntPtr.Zero) Marshal.FreeHGlobal(commentPtr);
        }
    }

    /// <summary>
    /// Lädt ein Passwort aus dem Windows Credential Manager.
    /// </summary>
    /// <param name="targetName">Der eindeutige Name des Credentials.</param>
    /// <returns>Das geladene Passwort als SecureString, oder null, wenn nicht gefunden oder Fehler.</returns>
    public static SecureString? LoadPassword(string targetName)
    {
        if (string.IsNullOrEmpty(targetName)) throw new ArgumentNullException(nameof(targetName));

        IntPtr credPtr = IntPtr.Zero; // Pointer, auf den API die Struktur schreibt
        SecureString? password = null;

        try
        {
            // 1. Credential lesen
            bool success = CredRead(targetName, CREDENTIAL_TYPE.GENERIC, 0, out credPtr);

            if (!success)
            {
                return null; // Credential nicht gefunden oder anderer Fehler
            }

            // 2. Passwortbytes aus der zurückgegebenen Struktur extrahieren
            // credPtr zeigt auf die CREDENTIAL Struktur, die von CredRead zugewiesen wurde
            CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));

            if (cred.CredentialBlob != IntPtr.Zero && cred.CredentialBlobSize > 0)
            {
                // Kopiere die Bytes aus dem unmanaged Speicher, den die API zurückgegeben hat
                byte[] passwordBytes = new byte[cred.CredentialBlobSize];
                Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, (int)cred.CredentialBlobSize);

                // 3. Erstelle SecureString aus den Bytes (UTF16 erwartet)
                // Wir erwarten, dass die Bytes UTF16 sind, da wir UTF16 bei CredWriteW geschrieben haben
                // Konvertiere Bytes (UTF16) zurück zu char[] und dann zu SecureString
                // Stelle sicher, dass die Bytezahl gerade ist, sonst ist es kein gültiges UTF16
                if (passwordBytes.Length % 2 != 0)
                {
                    Console.WriteLine("Warning: Credential Blob size is not a multiple of 2, cannot convert to UTF16 characters.");
                    HighlySecureAuthenticatedVersionedCipher.ClearBytes(passwordBytes); // Lösche die Bytes trotzdem
                    return null; // Fehler: Ungültiges Format
                }
                char[] passwordChars = new char[passwordBytes.Length / 2];
                Buffer.BlockCopy(passwordBytes, 0, passwordChars, 0, passwordBytes.Length);

                password = new SecureString();
                foreach (char c in passwordChars)
                {
                    password.AppendChar(c);
                }
                password.MakeReadOnly(); // Wichtig! SecureString abschließen

                // 4. Lösche die temporäre managed Kopie der Passwort-Bytes
                HighlySecureAuthenticatedVersionedCipher.ClearBytes(passwordBytes);
            }
            else
            {
                // Credential gefunden, aber kein PasswortBlob vorhanden (sollte nicht vorkommen für Passwörter)
                Console.WriteLine("Warning: Credential found, but no password data in blob.");
            }

            return password; // Gib SecureString zurück
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception loading credential: {ex.Message}");
            return null;
        }
        finally
        {
            // 5. Speicher, den die API zugewiesen hat (credPtr), MUSS freigegeben werden!
            if (credPtr != IntPtr.Zero)
            {
                CredFree(credPtr);
            }
        }
    }

    /// <summary>
    /// Löscht ein Passwort aus dem Windows Credential Manager.
    /// </summary>
    /// <param name="targetName">Der eindeutige Name des Credentials.</param>
    /// <returns>True, wenn erfolgreich oder nicht gefunden, False bei anderem Fehler.</returns>
    public static bool DeletePassword(string targetName)
    {
        if (string.IsNullOrEmpty(targetName)) throw new ArgumentNullException(nameof(targetName));

        // Credential löschen
        bool success = CredDelete(targetName, CREDENTIAL_TYPE.GENERIC, 0);

        if (!success)
        {
            int error = Marshal.GetLastWin32Error();
            // ERROR_NOT_FOUND (1168) bedeutet, es gab nichts zu löschen, was in Ordnung ist.
            if (error != 1168)
            {
                Console.WriteLine($"Error deleting credential: {error} (Win32 Error)");
                return false; // Fehler
            }
        }

        return true; // Erfolgreich gelöscht oder war nicht vorhanden
    }
}