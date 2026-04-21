# XboxRecomp

XboxRecomp is a tool that converts Xbox executables (xbe file) into C++ code, which can then be recompiled for any platform. Currently, it only supports [x86 platforms](https://en.wikipedia.org/wiki/X86), but support for [ARM](https://en.wikipedia.org/wiki/ARM_architecture_family) is planned.

This project was built (and therefore inspired) from [XenonRecomp](https://github.com/hedge-dev/XenonRecomp), (Sometimes in a questionable way as assembly isn't my expertise.).

> [!CAUTION]
> This project isn't a plug and play or a drag drop XBE to EXE converter, this tool ONLY converts the game code to C++, which is NOT going to function correctly without a runtime backing it.
> You will have to emulate Xbox Kernel (at least partially), implement graphics, sounds, controls as well as other manual tweaks to make the game working properly, an example of a project doing that is [Shadow Recompiled.](https://github.com/FoxWorkshop/ShadowRecomp)

## Implementation Details

### Instructions
> [!NOTE]
> Despite the original Xbox using x86 just like PC, the instructions still get converted to c++, while it's possible to bypass this and just call the functions directly from a XBE file, I wanted a portable solution that could support multiplatforms and not just PC, so I ended making this tool anyway. I also wanted to learn more about x86 and the process of recompilation.

### Global Variables

Global variables are not recompiled, instead, when the recompilated game needs to access them, it will browse them in the reserved memory region that contains all the XBE data. When the game needs to access a variable,
the macro `X86_LOAD_UXX` will be used (XX being the size of the variable, 8, 16, 32), and it if needs to store a value, it will use `X86_STORE_UXX`, this is done automatically by the recompiler by detecting instruction like `mov`, so you don't have to worry about implementing that, just something that you need to know.

### Indirect / Virtual Functions

Virtual function calls are resolved by creating a "perfect hash table" at runtime, where dereferencing a 64-bit pointer (using the original instruction address multiplied by 2) gives the address of the recompiled function. It relies on function addresses being placed after the valid XBE memory region in the base memory pointer. These regions are exported as macros in the output `x86_config.h` file.


### Jump Tables

Jump tables often have predictable assembly patterns, making them easy to detect statically. XboxAnalyse has logic for detecting jump tables (at least in Shadow The Hedgehog) but it's not perfect, a few are still missed so it's up to the user to manually extract them through ida / ghidra.
Variations in other games may also require modifications to the detection logic. 

XboxAnalyse generates a TOML file containing detected jump tables, which can be referenced in the main TOML config file. This allows the recompiler to generate real switch cases for these jump tables.

### Function Boundary Analysis

XboxAnalyse includes a function boundary analyzer that works in most cases, but is very far from perfect.

Currently, many functions are missed during analyse mostly because XBE file has many segments that contain functions that don't always follow the regular rules than .text use. (e.g 16 bytes pattern, predictable start address etc.).

Do not expect to get all your functions extracted and analysed, some will need manual size fix and others will need full manual implementation (e.g start address and size). You can add the missing functions in the TOML file before running XboxRecomp.

### Exceptions

XBE File contains SEH functions which handle exceptions, those functions are usually assigned in a regular game function with a consistent pattern (e.g push 0x0FFFFFFFF -> push offset seh_XXXXXX).

Sometimes, functions that assign SEH function has orphan blocks, meaning it has block code that is only supposed to be read if the code fail and the exception runs.
While it's rare, those functions might fail in recompilation, they might need manual handle.


### Patch Mechanisms

XboxRecomp defines X86 functions in a way that makes them easy to hook, using techniques in the Clang compiler. By aliasing a X86 function to an "implementation function" and marking the original function as weakly linked, users can override it with a custom implementation while retaining access to the original function:

```cpp
X86_FUNC_IMPL(__imp__sub_XXXXXXXX);
X86_FUNC(sub_XXXXXXXX)
{
    __imp__sub_XXXXXXXX(ctx, base);
}
```

Additionally, mid-asm hooks can be inserted directly into the translated C++ code at specific instruction addresses. The recompiler inserts these function calls, and users are responsible for implementing them in their recompilation project. The linker resolves them during compilation.


> [!NOTE]
> It's also possible to hook functions in a more "traditional" way with human readable parameters, but you would need to implement this manually like Shadow Recompiled does.
> If you do so, you would need to handle [calling convention type](https://www.geeksforgeeks.org/cpp/calling-conventions-in-c-cpp/) as well as [ESP](https://www.c-jump.com/CIS77/ASM/Stack/S77_0040_esp_register.htm),
> in that case, always pay extra attention to the original type and the number of ESP the function originally return, otherwise you will corrupt the stack and crash the game.


## Usage

### XboxAnalyse

XboxAnalyse, when used as a command-line application, allows an XBE file to be passed as an input argument to output a TOML file containing all the detected jump tables in the executable:

```
XboxAnalyse [input XBE file path] [output jump table TOML file path]
```

However, as explained in the earlier sections, due to variations between games, additional support may be needed to handle different patterns.

[An example jump table TOML file can be viewed in the Shadow Recompiled repository.](https://github.com/FoxWorkshop/ShadowRecomp/raw/refs/heads/master/ShadowRecompLib/config/jumpTables.toml) 

### XboxRecomp

XboxRecomp accepts a TOML file with recompiler configurations and the path to the `x86_context.h` file located in the XboxUtils directory:

```
XboxRecomp [input TOML file path] [input X86 context header file path]
```

[An example recompiler TOML file can be viewed in the Shadow Recompiled repository.](https://github.com/FoxWorkshop/ShadowRecomp/raw/refs/heads/master/ShadowRecompLib/config/recompConfig.toml)

If you don't execute the program through command line, it will look for "jumpTable.toml" and "recompConfig.toml in the same folder than XboxRecomp.exe.

#### Main

```toml
[main]
file_path = "default.xbe"
out_directory_path = "../extracted"
switch_table_file_path = "out.toml"
```

All the paths are relative to the directory where the TOML file is stored.

Property|Description
-|-
file_path|Path to the XBE file.
out_directory_path|Path to the directory that will contain the output C++ code. This directory must exist before running the recompiler.
switch_table_file_path|Path to the TOML file containing the jump table definitions. The recompiler uses this file to convert jump tables to real switch cases.


#### Explicit Function Boundaries

```toml
functions = [
    { address = 0x125B0, size = 0x146 },    
	{ address = 0x31c720, size = 0x1489 },	
	{ address = 0x66A80, size = 0x8A },
]
```

You can define function boundaries explicitly using the `functions` property if XboxAnalyse fails to analyze them correctly, for example, with functions containing jump tables.

#### Invalid Instruction Skips

```toml
invalid_instructions = [
    { data = 0x00000000, size = 4 }, # Padding
    { data = 0x831B1C90, size = 8 }, # C++ Frame Handler
    { data = 0x8324B3BC, size = 8 }, # C Specific Frame Handler
    { data = 0x831C8B50, size = 8 },
    { data = 0x00485645, size = 44 } # End of .text
]
```

In the `invalid_instructions` property, you can define 8-bit integer values that instruct the recompiler to skip over certain bytes when it encounters them.

#### Invalid Addresses Skips

```
    banned_addresses = [
    { start = 0x41FF90, end = 0x423B38 }, # variables xgraphics    
	{ start = 0x37E8FD, end = 0x37E91F }, # jmp table mid function	
	{ start = 0x37FE7D, end = 0x37FE9F }, # jmp table mid function
	{ start = 0x37FE03, end = 0x37FE0F }, # jmp table mid function	
	{ start = 0x37FEEA, end = 0x37FEFB }, # jmp table mid function	
	{ start = 0x380086, end = 0x380097 }, # jmp table mid function		
	{ start = 0x37E96A, end = 0x37E97B }, # jmp table mid function		
	{ start = 0x37EA99, end = 0x37EABB }, # jmp table mid function	
	{ start = 0x37EB06, end = 0x37EB17 }, # jmp table mid function	
]
```

Similar to invalid instruction, `banned_addresses` allow you to skip any instruction between a defined addresses ranges. For example, Shadow Recompiled uses it to skip jmp tables that are literally inside a function which prevent their recompilation to work properly. Making the recompiler skipping that part allows the function to be rebuilt properly.


#### Mid-asm Hooks (todo finish)

```toml
[[midasm_hook]]
name = "IndexBufferLengthMidAsmHook"
address = 0x82E26244
registers = ["ecx"]
```

```cpp
void IndexBufferLengthMidAsmHook(X86Register& ecx)
{
    // ...
}
```

### Tests (may or may not implement)

## Building

The project requires CMake 3.20 or later and Clang 18 or later to build. Since the repository includes submodules, ensure you clone it recursively.

Compilers other than Clang have not been tested and are not recommended, including for recompilation output. The project relies on compiler-specific intrinsics and techniques that may not function correctly on other compilers, and many optimization methods depend on Clang's code generation.

On Windows, you can use the clang-cl toolset and open the project in Visual Studio's CMake integration.

## Special Thanks

- Caustik for [very useful XBE Documentation](https://xbdev.net/fileformats/xbe/NonOfficialXBEFileFormat.pdf).
- [Sewer56](https://github.com/sewer56) Multiple tips with x86 analyse.
- [Skyth](https://github.com/blueskythlikesclouds) Provided information of how recompilation overall works which was reproduced here.
