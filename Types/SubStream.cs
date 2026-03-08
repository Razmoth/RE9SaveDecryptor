namespace RE9SaveDecryptor.Types;
public class SubStream : Stream
{
    private readonly Stream _baseStream;
    private readonly long _offset;
    private readonly long _size;
    private long _position;

    public override bool CanRead => _baseStream.CanRead;
    public override bool CanSeek => _baseStream.CanSeek;
    public override bool CanWrite => _baseStream.CanWrite;
    public override long Length => _size;
    public override long Position 
    { 
        get => _position; 
        set => Seek(value, SeekOrigin.Begin);
    }
    public SubStream(Stream stream, long offset, long? size)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegative(offset, nameof(offset));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, stream.Length, nameof(offset));

        _baseStream = stream;
        _offset = offset;
        _size = _baseStream.Length - _offset;

        if (size.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(size.Value, nameof(size));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(size.Value, _baseStream.Length - offset, nameof(size));

            _size = size.Value;
        }
        
        Position = 0;
    }
    public override void Flush() => throw new NotImplementedException();
    public override void SetLength(long value) => throw new NotImplementedException();
    public override long Seek(long offset, SeekOrigin origin)
    {
        long position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _size + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };

        if (position < 0 || position > _size)
        {
            throw new IOException("Attempted to seek outside substream !!");
        }

        _position = position;
        _baseStream.Position = _offset + position;

        return position;
    }
    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, buffer.Length, nameof(offset));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, buffer.Length - offset, nameof(count));
    
        if (_position >= _size)
        {
            return 0;
        }

        count = (int)Math.Min(count, _size - _position);

        Position = _position;

        int read = _baseStream.Read(buffer, offset, count);

        _position += read;

        return read;
    }
    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, buffer.Length, nameof(offset));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, buffer.Length - offset, nameof(count));

        if (_position + count > _size)
        {
            throw new IOException("Attempted to write outside substream !!");
        }

        Position = _position;

        _baseStream.Write(buffer, offset, count);

        _position += count;
    }
}