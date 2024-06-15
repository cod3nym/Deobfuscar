using System.Text;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;

namespace Deobfuscar;

public class Deobfuscator
{
    private readonly ModuleDefinition _module;
    private TypeDefinition _runtimeType = null!;
    private byte[] _stringData = null!;
    private readonly List<MethodDefinition> _decryptionMethods = new();

    public Deobfuscator(ModuleDefinition module)
    {
        _module = module;
    }

    public void Process()
    {
        FindRuntime();
        _decryptionMethods.AddRange(_runtimeType.Methods.Where(m =>
            m.IsPublic && m.Signature?.ReturnType == _module.CorLibTypeFactory.String));
        DecryptStringData();
        ProcessBodies();
    }

    private void ProcessBodies()
    {
        foreach (var type in _module.GetAllTypes().Where(t => t.Methods.Count > 0 && t != _runtimeType))
        {
            foreach (var method in type.Methods.Where(m => m.CilMethodBody != null))
            {
                foreach (var instruction in method.CilMethodBody!.Instructions)
                {
                    if (instruction.OpCode.OperandType != CilOperandType.InlineMethod)
                        continue;

                    if (!_decryptionMethods.Contains(instruction.Operand))
                        continue;

                    var callTarget = instruction.Operand as MethodDefinition
                                     ?? throw new InvalidOperationException();

                    instruction.OpCode = CilOpCodes.Ldstr;
                    instruction.Operand = GetString(callTarget);
                }
            }
        }
    }

    private void DecryptStringData()
    {
        for (int i = 0; i < _stringData.Length; i++)
        {
            _stringData[i] = (byte)(_stringData[i] ^ i ^ 0xAA);
        }
    }

    private string GetString(MethodDefinition getMethod)
    {
        var cilInstructions = getMethod.CilMethodBody!.Instructions.Where(i => i.IsLdcI4()).ToList();
        cilInstructions.RemoveRange(0, 2);


        return Encoding.UTF8.GetString(_stringData, cilInstructions[0].GetLdcI4Constant(),
            cilInstructions[1].GetLdcI4Constant());
    }

    private void FindRuntime()
    {
        var typeCandidates = _module.GetAllTypes().Where(t => t.GetStaticConstructor() != null && t.Fields.Count == 3);

        foreach (var type in typeCandidates)
        {
            if (!type.Fields.Any(f =>
                    f.Signature!.FieldType.IsValueType && f.Signature.FieldType.Resolve()!.IsExplicitLayout))
                continue;

            var dataField = type.Fields.First(f => f.HasFieldRva && f.Signature!.FieldType.IsValueType);

            _stringData = dataField.FieldRva!.ToReference().CreateReader().ReadToEnd();

            Console.WriteLine(
                $"Identified String Encryption Runtime: {type.Name} Token: {type.MetadataToken.ToString()}");
            _runtimeType = type;
            return;
        }
    }
}
