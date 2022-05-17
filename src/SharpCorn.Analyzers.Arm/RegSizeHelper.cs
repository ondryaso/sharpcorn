// RegSizeHelper.cs
// Author: Ondřej Ondryáš

namespace SharpCorn.Analyzers.Arm;

public static class RegSizeHelper
{
    public static bool IsLong(int regNum, int sizeBytes)
    {
        return sizeBytes switch
        {
            4 => Is4Bytes(regNum),
            8 => regNum is >= 14 and <= 45,
            16 => regNum is >= 50 and <= 65,
            36 => regNum == 139, // CP_REG
            _ => false
        };
    }

    public static bool IsValidRegister(int regNum)
    {
        return Is4Bytes(regNum) ||
            regNum is (>= 50 and <= 65) // Q0 do Q15
                or (>= 14 and <= 45)    // D0 to D31
                or 139;
    }

    private static bool Is4Bytes(int regNum)
        => regNum is (>= 66 and <= 78) // R0 to R12
            or >= 79 and <= 110        // S0 to S31
            or 1 or 2 or 3 or 13 or 12 or 10 or 11
            or 111 or 113 or 4 or 6 or 8 or 114 or 115 or 116
            or (>= 118 and <= 126) or 117;
}
