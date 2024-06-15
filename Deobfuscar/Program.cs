// See https://aka.ms/new-console-template for more information

using AsmResolver.DotNet;
using Deobfuscar;

string filepath = args[0];

if (!File.Exists(filepath))
{
    Console.WriteLine($"File not found: {filepath}");
    return;
}

var module = ModuleDefinition.FromFile(filepath);
var deobfuscator = new Deobfuscator(module);
deobfuscator.Process();

string filename = Path.GetFileName(filepath);
filepath = filepath.Replace(filename, $"unpacked_{filename}");

module.Write(filepath);

Console.WriteLine($"Success, saved output file to {filepath}");


