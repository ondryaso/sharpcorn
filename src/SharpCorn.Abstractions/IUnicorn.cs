using SharpCorn.Abstractions.Enums;
using SharpCorn.Callbacks;

// ReSharper disable InconsistentNaming

namespace SharpCorn.Abstractions;

public interface IUnicorn : IUnicornContext
{
    // uc_version
    (uint Major, uint Minor) Version { get; }

    /// <summary>
    /// Checks whether the used Unicorn library version matches the one this binding was built for.
    /// </summary>
    /// <param name="throwIfNot">If true, this method will throw an <see cref="UnicornException"/> on mismatch.</param>
    /// <param name="considerMinor">If true, different 'minor' version numbers will be considered mismatching.</param>
    /// <returns>True if Unicorn is the same version this binding was build for.</returns>
    bool CheckIfBindingMatchesLibrary(bool throwIfNot = false, bool considerMinor = true);

    // uc_ctl, UC_CTL_UC_MODE, read
    int CurrentMode { get; }

    // uc_ctl, UC_CTL_UC_PAGE_SIZE, read/write
    uint CurrentPageSize { get; set; }

    // uc_ctl, UC_CTL_UC_ARCH, read
    int CurrentArch { get; }

    // uc_ctl, UC_CTL_UC_TIMEOUT, read
    ulong CurrentTimeout { get; }

    // uc_ctl, UC_CTL_UC_EXITS_CNT, read
    nuint CurrentNumberOfExits { get; }

    // uc_ctl, UC_CTL_UC_EXITS, read/write
    ulong[] Exits { get; set; }

    // uc_ctl, UC_CTL_CPU_MODEL, read/write
    int CpuModel { get; set; }

    // uc_arch_supported
    bool IsArchSupported(Architecture architecture);

    // uc_query
    ulong Query(QueryType type);

    // uc_ctl, UC_CTL_UC_USE_EXITS, write
    void EnableMultipleExits();

    // Missing: uc_ctl, UC_CTL_TB_REQUEST_CACHE, read

    // uc_ctl, UC_CTL_TB_REMOVE_CACHE, write
    void RemoveTbCache(ulong begin, ulong end);

    void GetExits(Span<ulong> target);
    void SetExits(ReadOnlySpan<ulong> exits);
    void SetExits(ReadOnlySpan<ulong> exits, int length);

    void MemWrite(ulong address, byte[] bytes);
    void MemWrite(ulong address, byte[] bytes, nuint size);
    void MemWrite(ulong address, ReadOnlySpan<byte> bytes);
    void MemWrite(ulong address, ReadOnlySpan<byte> bytes, nuint size);

    byte[] MemRead(ulong address, nuint size);
    void MemRead(ulong address, byte[] target);
    void MemRead(ulong address, byte[] target, nuint size);
    void MemRead(ulong address, Span<byte> target);
    void MemRead(ulong address, Span<byte> target, nuint size);

    void EmuStart(ulong start, ulong until, ulong timeout = 0, ulong count = 0);

    void EmuStop();

    /// <summary>
    /// Adds an unmanaged Unicorn hook using a pointer to a callback function. Corresponds to uc_hook_add.
    /// </summary>
    /// <remarks>
    /// This method is unsafe and should be used with caution. The caller must ensure that <paramref name="callbackPointer"/>
    /// is a valid pointer to a function that matches the signature of the callback, and that it is not garbage collected or
    /// relocated while the hook is active. The caller must manually clean up the hook using <see cref="RemoveNativeHook(nuint)"/>.
    /// <para/>
    /// See the Unicorn API documentation for more information on the hook types and callback signatures.
    /// </remarks>
    /// <param name="callbackPointer">The pointer to the callback function, passed as-is to uc_hook_add.</param>
    /// <param name="type">The type of the hook constant according to the Unicorn API (see the uc_hook_type enum).</param>
    /// <param name="startAddress">The start address for the hook.</param>
    /// <param name="endAddress">The end address for the hook.</param>
    /// <param name="userData">User data to be passed to the callback. This is an opaque, pointer-sized value.</param>
    /// <returns>Unicorn's hook handle (to be used in <see cref="RemoveNativeHook(nuint)"/>).</returns>
    /// <exception cref="UnicornException">The hook could not be added. Refer to the error code for more details.</exception>
    /// <seealso cref="AddNativeHook(Delegate, int, ulong, ulong, nuint)"/>
    nuint AddNativeHook(IntPtr callbackPointer, int type, ulong startAddress, ulong endAddress, nuint userData = 0);

    /// <summary>
    /// Adds an unmanaged Unicorn hook using a method delegate as a callback function. Corresponds to uc_hook_add.
    /// Uses <see cref="System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate{TDelegate}(TDelegate)"/>
    /// to create an unmanaged thunk for the managed delegate.
    /// </summary>
    /// <remarks>
    /// The caller must ensure that <paramref name="callback"/> is a method that matches the signature of the native callback.
    /// The caller must manually clean up the hook using <see cref="RemoveNativeHook(nuint)"/>.
    /// We will ensure that the delegate is not garbage collected while the hook is active.
    /// <para/>
    /// See the Unicorn API documentation for more information on the hook types and callback signatures.
    /// </remarks>
    /// <param name="callback">The callback function delegate.</param>
    /// <param name="type">The type of the hook constant according to the Unicorn API (see the uc_hook_type enum).</param>
    /// <param name="startAddress">The start address for the hook.</param>
    /// <param name="endAddress">The end address for the hook.</param>
    /// <param name="userData">User data to be passed to the callback. This is an opaque, pointer-sized value.</param>
    /// <returns>Unicorn's hook handle (to be used in <see cref="RemoveNativeHook(nuint)"/>).</returns>
    /// <exception cref="UnicornException">The hook could not be added. Refer to the error code for more details.</exception>
    nuint AddNativeHook(Delegate callback, int type, ulong startAddress, ulong endAddress, nuint userData = 0);

    IUnicornHookRegistration AddCodeHook(CodeHookCallback callback, ulong startAddress, ulong endAddress);

    IUnicornHookRegistration AddBlockHook(CodeHookCallback callback, ulong startAddress, ulong endAddress);

    IUnicornHookRegistration AddInterruptHook(InterruptHookCallback callback);

    IUnicornHookRegistration AddInvalidInstructionHook(InvalidInstructionHookCallback callback);

    IUnicornHookRegistration AddMemoryHook(MemoryHookCallback callback, MemoryHookType hookType, ulong startAddress,
        ulong endAddress);

    IUnicornHookRegistration AddInvalidMemoryAccessHook(InvalidMemoryAccessCallback callback, MemoryHookType hookType,
        ulong startAddress,
        ulong endAddress);

    void RemoveHook(IUnicornHookRegistration registration);
    void RemoveNativeHook(nuint hookId);

    void MemMap(ulong address, nuint size, MemoryPermissions permissions);
    void MemMap(ulong address, nuint size, MemoryPermissions permissions, IntPtr memoryPointer);
    void MemMap(ulong address, nuint size, MMIOReadCallback? readCallback, MMIOWriteCallback? writeCallback);

    /// <summary>
    /// Adds a MMIO region that invokes the provided callbacks when read from or written to.
    /// The callbacks are specified as pointers to functions.
    /// The memory permissions will be determined by the presence of the read and write callbacks.
    /// Corresponds to uc_mmio_map.
    /// </summary>
    /// <remarks>
    /// This method is unsafe and should be used with caution. The caller must ensure that the provided pointers
    /// refer to functions that match the expected signature of the callback.
    /// <b>The caller must ensure</b> that the callbacks are not garbage collected or relocated while the hook is active.
    /// <para/>
    /// See the Unicorn API documentation for more information on the callback signatures.
    /// </remarks>
    /// <param name="address">The starting address of the new MMIO region.</param>
    /// <param name="size">The size of the MMIO region.</param>
    /// <param name="readCallbackPointer">The pointer to the function that will handle reads from the MMIO region,
    ///     or 0 to mark the region as unreadable.</param>
    /// <param name="writeCallbackPointer">The pointer to the function that will handle writes to the MMIO region,
    ///     or 0 to mark the region as unwritable.</param>
    /// <param name="readCallbackUserData">User data to be passed to the read callback. This is an opaque, pointer-sized value.</param>
    /// <param name="writeCallbackUserData">User data to be passed to the write callback. This is an opaque, pointer-sized value.</param>
    /// <exception cref="UnicornException">The memory could not be mapped. Refer to the error code for more details.</exception>
    /// <seealso cref="MemMapUnmanaged(ulong, nuint, Delegate?, Delegate?, nuint, nuint)"/>
    /// <seealso cref="MemMap(ulong, nuint, MMIOReadCallback?, MMIOWriteCallback?)"/>
    void MemMapUnmanaged(ulong address, nuint size, IntPtr readCallbackPointer, IntPtr writeCallbackPointer,
        nuint readCallbackUserData = 0, nuint writeCallbackUserData = 0);

    /// <summary>
    /// Adds a MMIO region that invokes the provided callbacks when read from or written to.
    /// The callbacks are specified as method delegates. The method uses <see
    /// cref="System.Runtime.InteropServices.Marshal.GetFunctionPointerForDelegate{TDelegate}(TDelegate)"/>
    /// to create an unmanaged thunk for the managed delegate.
    /// The memory permissions will be determined by the presence of the read and write callbacks.
    /// Corresponds to uc_mmio_map.
    /// </summary>
    /// <remarks>
    /// This method should be used with caution. The caller must ensure that the provided delegates
    /// match the expected signature of the callback.
    /// The caller must ensure that the delegates are not garbage collected or relocated while the hook is active.
    /// This is <b>not</b> done by SharpCorn (unlike in <see cref="AddNativeHook(Delegate, int, ulong, ulong, nuint)"/>).
    /// <para/>
    /// See the Unicorn API documentation for more information on the callback signatures.
    /// </remarks>
    /// <param name="address">The starting address of the new MMIO region.</param>
    /// <param name="size">The size of the MMIO region.</param>
    /// <param name="readCallback">The delegate for a method function that will handle reads from the MMIO region,
    ///     or <see langword="null"/> to mark the region as unreadable.</param>
    /// <param name="writeCallback">The delegate for a method that will handle writes to the MMIO region,
    ///     or <see langword="null"/> to mark the region as unwritable.</param>
    /// <param name="readCallbackUserData">User data to be passed to the read callback. This is an opaque, pointer-sized value.</param>
    /// <param name="writeCallbackUserData">User data to be passed to the write callback. This is an opaque, pointer-sized value.</param>
    /// <exception cref="UnicornException">The memory could not be mapped. Refer to the error code for more details.</exception>
    /// <seealso cref="MemMap(ulong, nuint, MMIOReadCallback?, MMIOWriteCallback?)"/>
    void MemMapUnmanaged(ulong address, nuint size, Delegate? readCallback, Delegate? writeCallback,
        nuint readCallbackUserData = 0, nuint writeCallbackUserData = 0);

    void MemUnmap(ulong address, nuint size);

    IUnicornContext MakeEmptyContext();
    IUnicornContext SaveContext();
    void SaveContext(IUnicornContext context);
    void RestoreContext(IUnicornContext context);
}

public interface IUnicornContext : IDisposable
{
    void RegWrite<T>(int registerId, T value) where T : unmanaged;
    T RegRead<T>(int registerId) where T : unmanaged;
    void RegRead<T>(int registerId, ref T target) where T : unmanaged;
    void RegWrite(int registerId, ReadOnlySpan<byte> bytes);
    void RegRead(int registerId, Span<byte> target);
    void RegBatchWrite<T>(ReadOnlySpan<int> registerIds, IEnumerable<T> values) where T : unmanaged;
    void RegBatchWrite<T>(ReadOnlySpan<int> registerIds, ReadOnlySpan<T> values) where T : unmanaged;
    void RegBatchRead<T>(ReadOnlySpan<int> registerIds, Span<T> target) where T : unmanaged;
    T[] RegBatchRead<T>(ReadOnlySpan<int> registerIds) where T : unmanaged;
}
