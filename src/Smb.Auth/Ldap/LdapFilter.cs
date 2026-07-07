using System.Globalization;
using System.Text;

namespace Smb.Auth.Ldap;

/// <summary>LDAP search-filter helpers (RFC 4515).</summary>
public static class LdapFilter
{
    /// <summary>
    /// Escapes a value for safe use inside a filter assertion (RFC 4515 §3): the special characters
    /// <c>* ( ) \ NUL</c> become <c>\HH</c>. Prevents LDAP filter injection when interpolating a
    /// client-supplied account name.
    /// </summary>
    public static string Escape(string value)
    {
        var sb = new StringBuilder(value.Length + 8);
        foreach (char c in value)
        {
            switch (c)
            {
                case '*': sb.Append("\\2a"); break;
                case '(': sb.Append("\\28"); break;
                case ')': sb.Append("\\29"); break;
                case '\\': sb.Append("\\5c"); break;
                case '\0': sb.Append("\\00"); break;
                default:
                    if (c < 0x20)
                        sb.Append('\\').Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                    else
                        sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }
}
