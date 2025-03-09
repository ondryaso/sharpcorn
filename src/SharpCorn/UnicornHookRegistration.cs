// UnicornHookRegistration.cs
// Author: Ondřej Ondryáš

using SharpCorn.Abstractions;

namespace SharpCorn;

public class UnicornHookRegistration : IUnicornHookRegistration, IEquatable<UnicornHookRegistration>
{
    internal nuint NativeHookId { get; init; }
    internal nuint ManagedHookId { get; init; }
    public IUnicorn Unicorn { get; }
    public Delegate Callback { get; }
    public ulong StartAddress { get; internal init; }
    public ulong EndAddress { get; internal init; }
    public int HookType { get; internal init; }

    internal UnicornHookRegistration(IUnicorn unicorn, Delegate callback)
    {
        Unicorn = unicorn;
        Callback = callback;
    }

    public void RemoveHook()
    {
        Unicorn.RemoveHook(this);
    }

    public bool Equals(UnicornHookRegistration? other) =>
        ReferenceEquals(Unicorn, other?.Unicorn)
        && NativeHookId.Equals(other.NativeHookId)
        && ManagedHookId == other.ManagedHookId;

    public bool Equals(IUnicornHookRegistration? other) =>
        other is UnicornHookRegistration hr
        && ReferenceEquals(Unicorn, other.Unicorn)
        && NativeHookId.Equals(hr.NativeHookId)
        && ManagedHookId == hr.ManagedHookId;

    public override bool Equals(object? obj) => obj is UnicornHookRegistration other && this.Equals(other);

    public override int GetHashCode() => HashCode.Combine(Unicorn, NativeHookId, ManagedHookId);

    public static bool operator ==(UnicornHookRegistration left, UnicornHookRegistration right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(UnicornHookRegistration left, UnicornHookRegistration right)
    {
        return !(left == right);
    }
}
