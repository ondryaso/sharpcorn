using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SharpCorn.Analyzers.Arm;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public class RegReadAnalyzer : DiagnosticAnalyzer
{
    private const string Category = "Registers";

    private static readonly DiagnosticDescriptor InvalidTargetType = new("UNICORN0001", "RegRead Target Type",
        @"The target read type doesn't match the size of the register which is {0} bytes.",
        Category, DiagnosticSeverity.Warning, true,
        "RegRead called with a type parameter that doesn't match the used register.");

    private static readonly DiagnosticDescriptor UnknownTargetType = new("UNICORN0002", "RegRead Target Type",
        @"The target read type is not a numeric type.",
        Category, DiagnosticSeverity.Info, true,
        "RegRead called with a type parameter that is not numeric.");

    private static readonly DiagnosticDescriptor UnknownRegister = new("UNICORN0003", "RegRead Target Register",
        @"Invalid or unimplemented register.",
        Category, DiagnosticSeverity.Warning, true,
        "RegRead called with a register ID that isn't supported by Unicorn.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; }

    public RegReadAnalyzer()
    {
        SupportedDiagnostics = ImmutableArray<DiagnosticDescriptor>.Empty.Add(InvalidTargetType).Add(UnknownTargetType)
                                                                   .Add(UnknownRegister);
    }

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCodeBlockStartAction<SyntaxKind>(cbCtx =>
        {
            if (cbCtx.OwningSymbol.Kind != SymbolKind.Method)
                return;

            cbCtx.RegisterSyntaxNodeAction((ctx) => DoAnalysis(ctx),
                SyntaxKind.InvocationExpression);
        });
    }

    private static void DoAnalysis(SyntaxNodeAnalysisContext context)
    {
        var model = context.SemanticModel;
        var invocationNode = (InvocationExpressionSyntax)context.Node;
        var methodSymbol = (IMethodSymbol)model.GetSymbolInfo(invocationNode).Symbol;
        var containingSymbol = methodSymbol.ContainingSymbol;

        if (methodSymbol.Name != "RegRead" || containingSymbol.Name is not ("Unicorn" or "IUnicornContext"))
            return;

        if (methodSymbol.TypeArguments.Length == 0)
            return;

        var firstArgument = invocationNode.ArgumentList.Arguments.First().Expression;

        if (firstArgument == null)
            return;

        var argumentValue = model.GetConstantValue(firstArgument);

        if (!argumentValue.HasValue || argumentValue.Value is not int argumentValueData)
            return;

        var typeArgument = methodSymbol.TypeArguments[0];

        var typeSize = typeArgument.SpecialType switch
        {
            SpecialType.System_SByte => 1,
            SpecialType.System_Byte => 1,
            SpecialType.System_Int16 => 2,
            SpecialType.System_UInt16 => 2,
            SpecialType.System_Int32 => 4,
            SpecialType.System_UInt32 => 4,
            SpecialType.System_Int64 => 8,
            SpecialType.System_UInt64 => 8,
            SpecialType.System_Decimal => 16,
            SpecialType.System_Single => 4,
            SpecialType.System_Double => 8,
            SpecialType.System_IntPtr => Unsafe.SizeOf<IntPtr>(),
            SpecialType.System_UIntPtr => Unsafe.SizeOf<UIntPtr>(),
            _ => -1
        };

        if (typeArgument.Name == "CoprocessorRegister")
            typeSize = 36;

        if (typeSize == -1)
        {
            var diagnostic = Diagnostic.Create(UnknownTargetType, invocationNode.GetLocation());
            context.ReportDiagnostic(diagnostic);

            return;
        }

        var isValid = RegSizeHelper.IsValidRegister(argumentValueData);
        var isCorrectSize = RegSizeHelper.IsLong(argumentValueData, typeSize);
        
        if (!isValid)
        {
            var diagnostic = Diagnostic.Create(UnknownRegister, invocationNode.GetLocation());
            context.ReportDiagnostic(diagnostic);
        }
        else if (!isCorrectSize)
        {
            var diagnostic = Diagnostic.Create(InvalidTargetType, invocationNode.GetLocation(), typeSize);
            context.ReportDiagnostic(diagnostic);
        }
    }
}
