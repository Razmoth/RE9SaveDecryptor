using System.Text;

namespace RE9SaveDecryptor.Helpers;

public static class BinaryReaderExtensions
{
    public static string ReadNullString(this BinaryReader reader, int? count = default)
    {
        StringBuilder sb = new(count ?? 0);
        
        int i = 0;
        while (!count.HasValue || i < count)
        {
            char b = reader.ReadChar();
            if (b == 0)
            {
                break;
            }

            sb.Append(b);
            i++;
        }

        return sb.ToString();
    }
}