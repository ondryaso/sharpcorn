using SharpCorn.Abstractions.Enums;

namespace SharpCorn.Abstractions;

public class UnicornException : Exception
{
    public int ErrorId { get; }
    public UnicornError Error { get; }

    public UnicornException(int errorId, string message)
        : base(message)
    {
        ErrorId = errorId;
        Error = (UnicornError)errorId;
    }
}
