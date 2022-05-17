using SharpCorn;
using SharpCorn.Abstractions;
using SharpCorn.Abstractions.Enums;
using SharpCorn.Constants;

namespace Test;

public class Program
{
    public static void Main(string[] args)
    {
        IUnicorn uni = new Unicorn(Architecture.Arm, EngineMode.Arm);
        var a = uni.RegRead<uint>(Arm.Register.Control);
        var b = uni.RegRead<uint>(4545);
    }
}
