using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace engineering.hansen.Kami
{
    static class Keyring
    {
        private static readonly Regex pubrx = new Regex("^pub:");
        private static readonly Regex subrx = new Regex("^sub:");
        private static readonly Regex uidrx = new Regex("^(u(id)|(at)):");
        private static readonly Regex sigrx = new Regex("^((sig)|(rev)):");
        private static readonly Dictionary<int, String> AsymAlgoIDs = new Dictionary<int, String>();
        private static readonly Dictionary<int, String> SymAlgoIDs = new Dictionary<int, String>();
        private static readonly Dictionary<int, String> DigestAlgoIDs = new Dictionary<int, String>();
        private static readonly Dictionary<String, String> Validities = new Dictionary<String, String>();
        private static readonly DateTime epoch = new DateTime(1970,1,1,0,0,0,0, System.DateTimeKind.Utc);
        private static readonly Dictionary<String, Certificate> keyring = new Dictionary<String, Certificate>();
        private static readonly String gnupg;

        private static String EpochToString(String epochstr)
        {
            if (epochstr == "")
                return "Never";
            else if (epochstr.Contains("T"))
                return DateTime.ParseExact(epochstr.Substring(0, 8),
                    "yyyymmdd", System.Globalization.CultureInfo.InstalledUICulture)
                    .ToString("MMMM dd, yyyy");
            else
                return epoch.AddSeconds(int.Parse(epochstr)).ToLocalTime().ToString("MMMM dd, yyyy");
        }

        private static String AsymAlgoIDToString(int id)
        {
            return AsymAlgoIDs.ContainsKey(id) ? AsymAlgoIDs[id] : "Unknown";
        }

        private static String DigestAlgoIDToString(int id)
        {
            return DigestAlgoIDs.ContainsKey(id) ? DigestAlgoIDs[id] : "Unknown";
        }

        private static String GetValidityString(String v)
        {
            return Validities.ContainsKey(v) ? Validities[v] : "Unknown";
        }

        static Keyring()
        {
            using (var registryKey = Registry.LocalMachine.OpenSubKey(@"Software\GnuPG"))
            {
                gnupg = (String)registryKey.GetValue("Install Directory") + @"\bin\gpg.exe";
            }

            AsymAlgoIDs.Add(1, "RSA");
            AsymAlgoIDs.Add(2, "RSA Encrypt-Only");
            AsymAlgoIDs.Add(3, "RSA Sign-Only");
            AsymAlgoIDs.Add(16, "Elgamal");
            AsymAlgoIDs.Add(17, "DSA");
            AsymAlgoIDs.Add(18, "ECDH");
            AsymAlgoIDs.Add(19, "ECDSA");
            AsymAlgoIDs.Add(20, "Vulnerable Elgamal");
            AsymAlgoIDs.Add(22, "EdDSA");

            SymAlgoIDs.Add(0, "None");
            SymAlgoIDs.Add(1, "IDEA");
            SymAlgoIDs.Add(2, "3DES");
            SymAlgoIDs.Add(3, "CAST5");
            SymAlgoIDs.Add(4, "Blowfish");
            SymAlgoIDs.Add(7, "AES");
            SymAlgoIDs.Add(8, "AES192");
            SymAlgoIDs.Add(9, "AES256");
            SymAlgoIDs.Add(10, "Twofish");
            SymAlgoIDs.Add(11, "CAMELLIA128");
            SymAlgoIDs.Add(12, "CAMELLIA192");
            SymAlgoIDs.Add(13, "CAMELLIA256");

            DigestAlgoIDs.Add(1, "MD5");
            DigestAlgoIDs.Add(2, "SHA1");
            DigestAlgoIDs.Add(3, "RIPEMD160");
            DigestAlgoIDs.Add(8, "SHA256");
            DigestAlgoIDs.Add(9, "SHA384");
            DigestAlgoIDs.Add(10, "SHA512");
            DigestAlgoIDs.Add(11, "SHA224");

            Validities.Add("o", "Unknown");
            Validities.Add("i", "Invalid");
            Validities.Add("d", "Disabled");
            Validities.Add("r", "Revoked");
            Validities.Add("e", "Expired");
            Validities.Add("-", "Unassigned");
            Validities.Add("q", "Undefined");
            Validities.Add("n", "Invalid");
            Validities.Add("m", "Marginal");
            Validities.Add("f", "Valid");
            Validities.Add("u", "Implicit");
            Validities.Add("w", "Well-known private part");
            Validities.Add("s", "Special");

            LoadKeyIDs();
        }

        public static Certificate GetCertificate(String keyid)
        {
            if (!keyring.ContainsKey(keyid))
                return null;
            if (keyring[keyid] == null)
                LoadCertificate(keyid);
            return keyring[keyid];
        }

        public static List<String> GetCertificateIDs()
        {
            var rv = new List<String>();
            foreach (var s in keyring.Keys)
                rv.Add(s);
            rv.Sort();
            return rv;
        }

        private static void LoadKeyIDs()
        {
            var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = gnupg,
                    Arguments = "--fixed-list-mode --with-fingerprint --with-colons --list-keys",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
            {
                var line = proc.StandardOutput.ReadLine();
                if (pubrx.IsMatch(line))
                    keyring.Add(line.Split(':')[4], null);
            }
            proc.WaitForExit();
        }

        private static List<String> GetInfo(String keyID)
        {
            var rv = new List<String>();
            var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = gnupg,
                    Arguments = "--fixed-list-mode --with-fingerprint --with-colons --list-sigs " + keyID,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
                rv.Add(proc.StandardOutput.ReadLine());
            proc.WaitForExit();
            return rv;
        }

        public static void LoadCertificate(String keyID)
        {
            List<String> rows = GetInfo(keyID);
            int rowidx = 0;

            while (rowidx < rows.Count)
            {
                while (rowidx < rows.Count && !pubrx.IsMatch(rows[rowidx]))
                    ++rowidx;
                if (rowidx >= rows.Count)
                    return;
                keyring[keyID] = new Certificate(rows, rowidx);
                ++rowidx;
            }
        }

        public class Certificate : IComparable<Certificate>
        {

            public class Signature
            {
                public readonly String Created;
                public readonly String Expires;
                public readonly String SigningAlgo;
                public readonly String DigestAlgo;
                public readonly String KeyID;
                public readonly String UserID;

                public Signature(String row)
                {
                    var fields = row.Split(':');
                    SigningAlgo = AsymAlgoIDToString(int.Parse(fields[3]));
                    KeyID = fields[4];
                    Created = EpochToString(fields[5]);
                    Expires = EpochToString(fields[6]);
                    DigestAlgo = DigestAlgoIDToString(int.Parse(fields[15]));
                    UserID = fields[9].Replace(@"\x3a", ":");
                    if (fields[0] == "rev")
                        KeyID = "Designated revoker: " + fields[9];
                }
            }

            public class UserID
            {
                public readonly List<Signature> Signatures = new List<Signature>();
                public readonly String Name;
                public readonly String Created;
                public readonly String Validity;

                public UserID(List<String> rows, int rowidx)
                {
                    var fields = rows[rowidx].Split(':');
                    Validity = GetValidityString(fields[1]);
                    Created = EpochToString(fields[5]);
                    Name = fields[9].Replace(@"\x3a", ":");
                    ++rowidx;
                    while (rowidx < rows.Count && sigrx.IsMatch(rows[rowidx]))
                    {
                        Signatures.Add(new Signature(rows[rowidx]));
                        ++rowidx;
                    }
                }
            }

            public class Subkey
            {
                public readonly List<Signature> Signatures = new List<Signature>();
                public readonly String Algo;
                public readonly String Created;
                public readonly String Expires;
                public readonly String Validity;
                public readonly String KeyID;
                public readonly String Fingerprint;
                public readonly int Length;

                public Subkey(List<String> rows, int rowidx)
                {
                    var fields = rows[rowidx].Split(':');

                    Validity = GetValidityString(fields[1]);
                    Length = int.Parse(fields[2]);
                    Algo = AsymAlgoIDToString(int.Parse(fields[3]));
                    KeyID = fields[4];
                    Created = EpochToString(fields[5]);
                    Expires = EpochToString(fields[6]);
                    if (fields[16] != "")
                        Algo += " with curve " + fields[16];

                    while (rows[rowidx].Split(':')[0] != "fpr")
                        ++rowidx;
                    Fingerprint = rows[rowidx].Split(':')[9];
                    ++rowidx;
                    while (rowidx < rows.Count && sigrx.IsMatch(rows[rowidx]))
                    {
                        Signatures.Add(new Signature(rows[rowidx]));
                        ++rowidx;
                    }
                }
            }

            public Certificate(List<String> rows, int rowidx)
            {
                subkeys.Add(new Subkey(rows, rowidx));
                var fields = rows[rowidx].Split(':');

                Validity = GetValidityString(fields[1]);
                Algo = AsymAlgoIDToString(int.Parse(fields[3]));
                KeyID = fields[4];
                Ownertrust = GetValidityString(fields[8]);
                if (fields[16] != "")
                    Algo += " with curve " + fields[16];

                ++rowidx;
                while (rowidx < rows.Count)
                {
                    if (pubrx.IsMatch(rows[rowidx]))
                        return;
                    else if (uidrx.IsMatch(rows[rowidx]))
                        uids.Add(new UserID(rows, rowidx));
                    else if (subrx.IsMatch(rows[rowidx]))
                        subkeys.Add(new Subkey(rows, rowidx));
                    ++rowidx;
                }
            }

            public readonly String Validity;
            public readonly String KeyID;
            public readonly String Ownertrust;
            private List<UserID> uids = new List<UserID>();
            private List<Subkey> subkeys = new List<Subkey>();
            public readonly String Algo;

            public int Length
            {
                get
                {
                    return subkeys[0].Length;
                }
            }
            public String Created
            {
                get
                {
                    return subkeys[0].Created;
                }
            }

            public String Expires
            {
                get
                {
                    return subkeys[0].Expires;
                }
            }

            public List<UserID>.Enumerator UserIDs
            {
                get
                {
                    return uids.GetEnumerator();
                }
            }

            public List<Subkey>.Enumerator Subkeys
            {
                get
                {
                    return subkeys.GetEnumerator();
                }
            }

            public String Fingerprint
            {
                get
                {
                    return subkeys[0].Fingerprint;
                }
            }

            public int CompareTo(Certificate c)
            {
                return KeyID.CompareTo(c.KeyID);
            }

            public String ToHTML()
            {
                var sb = new StringBuilder();
                sb.Append(@"<html>
  <head>
    <title>Certificate 0x");
                sb.Append(KeyID);
                sb.Append(@"</title>
  </head>
  <body>
    <h1>Certificate 0x");
                sb.Append(KeyID);
                sb.Append(@"</h1>
    <ul>
");
                sb.Append(@"      <li><b>Fingerprint: </b>");
                sb.Append(Fingerprint);
                sb.Append(@"</li>
      <li><b>Created: </b>");
                sb.Append(Created);
                sb.Append(@"</li>
      <li><b>Expires: </b>");
                sb.Append(Expires);
                sb.Append(@"</li>
      <li><b>Validity: </b>");
                sb.Append(Validity);
                sb.Append(@"</li>
      <li><b>Ownertrust: </b>");
                sb.Append(Ownertrust);
                sb.Append(@"</li>
      <li><b>Algorithm: </b>");
                sb.Append(Algo);
                sb.Append("-");
                sb.Append(Length);
                sb.Append(@"</li>
    </ul>
    <h2>User IDs</h2>
    <ul>
");
                foreach (var uid in uids)
                {
                    sb.Append(@"    <li><b>");
                    sb.Append(uid.Name.Replace("<", "&lt;").Replace(">", "&gt;"));
                    sb.Append(@"</b><br>
      <b>Last Updated: </b>");
                    sb.Append(uid.Created);
                    sb.Append(@"<br>
      <b>Validity: </b>");
                    sb.Append(uid.Validity);
                    sb.Append(@"<br>
      <b>Signed by: </b>
      <ul>
");
                    foreach (var s in uid.Signatures)
                    {
                        sb.Append(@"        <li><b>");
                        sb.Append(s.UserID.Replace("<", "&lt;").Replace(">", "&gt;"));
                        sb.Append("</b>, keyid 0x");
                        sb.Append(s.KeyID);
                        sb.Append(@"<br>
        <b>Created: </b>");
                        sb.Append(s.Created);
                        sb.Append(@"<br>
        <b>Expires: </b>");
                        sb.Append(s.Expires);
                        sb.Append(@"<br>
        <b>Signing algorithm: </b>");
                        sb.Append(s.SigningAlgo);
                        sb.Append(" + ");
                        sb.Append(s.DigestAlgo);
                        sb.Append(@"<br></li>");
                    }
                    sb.Append(@"      </ul>
");
                }
                sb.Append(@"    </ul>
    <h2>Subkeys</h2>
    <ul>
");
                foreach (var sk in subkeys)
                {
                    sb.Append(@"      <li><b>0x");
                    sb.Append(sk.KeyID);
                    sb.Append(@"</b><br>
<b>Fingerprint: </b>");
                    sb.Append(sk.Fingerprint);
                    sb.Append(@"<br>
<b>Algorithm: </b>");
                    sb.Append(sk.Algo);
                    sb.Append("-");
                    sb.Append(sk.Length);
                    sb.Append(@"<br>
<b>Created: </b>");
                    sb.Append(sk.Created);
                    sb.Append(@"<br>
<b>Expires: </b>");
                    sb.Append(sk.Expires);
                    if (sk.Signatures.Count > 0)
                        sb.Append(@"<br>
<b>Signatures:</b><ul>");
                    else
                        sb.Append(@"<br>
");
                    foreach (var sig in sk.Signatures)
                    {
                        sb.Append(@"        <li><b>");
                        sb.Append(sig.UserID.Replace("<", "&lt;").Replace(">", "&gt;"));
                        sb.Append("</b>, keyid 0x");
                        sb.Append(sig.KeyID);
                        sb.Append(@"<br>
        <b>Created: </b>");
                        sb.Append(sig.Created);
                        sb.Append(@"<br>
        <b>Expires: </b>");
                        sb.Append(sig.Expires);
                        sb.Append(@"<br>
        <b>Signing algorithm: </b>");
                        sb.Append(sig.SigningAlgo);
                        sb.Append(" + ");
                        sb.Append(sig.DigestAlgo);
                        sb.Append(@"</li>");
                    }

                    if (sk.Signatures.Count > 0)
                        sb.Append(@"
      </ul>");
                }
                sb.Append(@"
    </ul>
  </body>
</html>");
                return sb.ToString();
            }
        }
    }
}
