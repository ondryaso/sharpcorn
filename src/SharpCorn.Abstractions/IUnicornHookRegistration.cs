// IUnicornHookRegistration.cs
// Author: Ondřej Ondryáš

namespace SharpCorn.Abstractions;

public interface IUnicornHookRegistration : IEquatable<IUnicornHookRegistration>
{
    IUnicorn Unicorn { get; }
    Delegate Callback { get; }
    ulong StartAddress { get; }
    ulong EndAddress { get; }
    int HookType { get; }
    void RemoveHook();
}
