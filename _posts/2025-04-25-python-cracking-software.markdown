---
layout: post
title: "Python 3.11 Binary Reversing: Patching Bytecode by Hand"
date:   2025-04-25 11:41:07 +0200
tags: python pyinstaller reverse-engineering bytecode
author: Gaztoof
---

Cracking software is rarely a simple task. Sometimes, it's about tackling an unfamiliar challenge and quickly figuring out how to make sense of complex systems.

At first, the task seemed relatively straightforward. I had experience unpacking PyInstaller executables, retrieving functional Python code, and simply editing it to get it working as I wished. However, Python 3.11 threw a wrench in the works. Since there were no fully supported decompilers for Python 3.11 at the time, I had to quickly familiarize myself with Python’s internal workings and how bytecode is structured.

In this post, I’ll walk through how I approached this challenge, what I learned about Python’s bytecode, and how I eventually removed all internet connectivity from the software, all while figuring things out along the way.

# Retrieving the Relevant .pyc

*To add to the challenge, I decided not to use **pyinstxtractor**.*

I started by opening the `.exe` file in **IDA Pro**, but it was taking an unusually long time to analyze—likely due to packing or compression. To streamline things, I used **OllyDump** from **x64dbg** to dump the process once the executable had unpacked itself at runtime.

After dumping, the binary loaded perfectly into IDA Pro. From there, I began analyzing the code from the **entry point**, skipping most of the boilerplate until I reached the parts that looked more relevant.

At one point in the disassembly, I found this interesting snippet of code where the executable imported C Python API functions like `PyEval_EvalCode` and `PyMarshal_ReadObjectFromString`:

![Importing functions in IDA](/assets/blogs/240425/RD0hrGn.png)

And later on, those functions would be used:

![PyEval and PyMarshal functions in IDA](/assets/blogs/240425/yvy0LYV.png)

From my research:

{% highlight c %}
PyObject *PyEval_EvalCode(PyObject *co, PyObject *globals, PyObject *locals)
{% endhighlight %}

This function executes a Python code object in a given global and local namespace—essentially running the contents of a `.pyc` file.

Before executing, though, the code object must be deserialized from its marshaled format. That’s the job of:

{% highlight c %}
PyAPI_FUNC(PyObject *) PyMarshal_ReadObjectFromString(const char *data, Py_ssize_t len)
{% endhighlight %}

This function reads a marshaled Python object from a byte string. In this context, it's responsible for reconstructing the code object from the bytecode blob.

I set a **breakpoint** on the call to `PyMarshal_ReadObjectFromString` in **x64dbg**. Once it hit, I inspected the stack and found that the filename of the current `.pyc` being loaded was also visible as a string, making it easy to determine which file was involved.

The only file that stood out during execution was **edit.pyc**—because right after `PyEval_EvalCode` was called on it, the application visibly transitioned: the execution appeared to "freeze", and the main software window opened, which confirmed its relevance.

I then dumped the `const char *data` parameter (the raw marshaled data) passed to `PyMarshal_ReadObjectFromString` directly from memory to a binary file.

Based on Python’s `.pyc` file format, I knew that the actual `.pyc` consists of a **16-byte header** followed by marshaled bytecode. So to reconstruct a working `.pyc` file, I simply had to prepend a valid header to the dumped blob (using [this research](https://nowave.it/python-bytecode-analysis-1.html#:~:text=ceval.c.-,Structure%20of%20.pyc%20files,-A%20pyc%20file)), though it seemed as the only crucial element was the magic number.

`A7 0D 0D 0A 00 00 00 00 00 00 00 00 00 00 00 00`

## Decompiling the Bytecode

I initially attempted to decompile the **edit.pyc** file using **decompyle3**, **uncompyle6**, and **pycdc** all of which are popular Python decompilers. However, I had no success. Neither tool was able to properly decompile the bytecode into usable source code. Given that Python 3.11 was still relatively new, I suspected that the decompilers hadn’t fully caught up with the latest changes.

Next, I turned to **[PyLingual.io](https://pylingual.io/)**, which gave me some results, but the output had so many errors that it was closer to pseudocode than functional code. Useful in that it gave me an idea of what the code structure looked like, but it wasn’t semantically correct. Yet it was enough to map out the program's logic and structure, which proved useful.

## Investigating Communications with the Server

I searched for any `http://` or `https://` strings—often an easy way to find API endpoints. I also checked for anything that might look suspicious or malicious, like attempts to access private files, communications with Discord webhooks, Telegram bots, or other external services but didn’t find anything meaningful.

However, I did find HTTP requests to API endpoints hosted at **labelmaker.cc**. The key functions involved were:

The functions I found were:
- **`signal()`** — This seemed to be the function used to authenticate the user.
- **`collectTrackingNumberUPS()`** — Associated with obtaining UPS packages tracking info.
- **`collectTrackingNumberFedex()`** — Similar, but for Fedex.
- **`reverseTrackingLookup()`** — Similar.
- **`logApi()`** — Used for logging user interactions with the app.

Here’s the relevant (*semantically incorrect*) Python code I found in the `signal()` function:
<details open>
<summary>def signal()</summary>
{% highlight python %}
def signal():
    E = 'message'
    D = 'success'
    C = 'status'
    B = 'links'
    A = 'license'
    mac = machineid.id()
    if mac == _G:
        return (_C, 'Something is blocking access to the licensing server. Label Maker AiO is unable to determine if this computer is licensed.')
    all_rows = license_db.all()
    if len(all_rows) == 0:
        return (_C, 'No license found. Please enter one.')
    license_id = {row[_C7] for row in all_rows}
    license_id = ''.join(license_id)
    license_key = {row[_C8] for row in all_rows}
    license_key = ''.join(license_key)
    res = requests.post('https://labelmaker.cc/_/api/connect', headers={'Accept': '*/*', 'Content-Type': 'application/json'}, data=json.dumps({_C7: license_id, _C8: license_key, 'machine_id': mac})).json()
    except:
        pass  # postinserted
    return (_C, 'licensing server is offline, unable to open software')
    try:
        if res[C][D] == 'False':
            return (_C, res[C][E])
    except:
        pass
    if res[C][D] == 'True':
        name = res[A][_A5]
        expiry = res[A]['expiration_date']
        currentMachines = res[A]['current_machines']
        maxMachines = res[A]['max_machines']
        product = res[A]['product']
        teleLink = res[B]['telegram']
        signalLink = res[B]['signal']
        mainLink = res[B]['main']
        telegramSupport = res[B]['telegram_support']
        signalSupport = res[B]['signal_support']
        return (_F, str(name), str(license_id), str(license_key), expiry, currentMachines, maxMachines, product, teleLink, signalLink, mainLink, telegramSupport, signalSupport)
    return (_C, res[C][E])
{% endhighlight %}
</details>

## Understanding the Authentication Flow

It was clear that only the `signal()` function was being used to authenticate the user. This meant that my goal was straightforward: disable any connectivity with the server and bypass that authentication process. However, the challenge arose because the **edit.pyc** file couldn’t simply be decompiled, edited, and recompiled (*due to unsupported/ineffective tools*).

So instead, I retrieved the **disassembled code** using a Python script i've made (*more on that in the [Injecting Constants and Tracking Changes section](#injecting-constants-and-tracking-changes)*), which presented the bytecode in a format like this: 

<details open>
<summary>Snippet</summary>
{% highlight python %}
1354         338 LOAD_GLOBAL             17 (NULL + requests)
             350 LOAD_ATTR                9 (post)
             360 LOAD_CONST              12 ('https://labelmaker.cc/_/api/connect')
             362 LOAD_CONST              13 ('*/*')
             364 LOAD_CONST              14 ('application/json')
             366 LOAD_CONST              15 (('Accept', 'Content-Type'))
             368 BUILD_CONST_KEY_MAP      2
             370 LOAD_GLOBAL             21 (NULL + json)
             382 LOAD_ATTR               11 (dumps)
             392 LOAD_GLOBAL             24 (_C7)
             404 LOAD_FAST                7 (license_id)
             406 LOAD_GLOBAL             26 (_C8)
             418 LOAD_FAST                8 (license_key)
             420 LOAD_CONST              16 ('machine_id')
             422 LOAD_FAST                5 (mac)
             424 BUILD_MAP                3
             426 PRECALL                  1
             430 CALL                     1
{% endhighlight %}
</details>

## Locating and Understanding the Key Variables

I saw that the variables **name**, **expiry**, **currentMachines**, **maxMachines**, **product**, **teleLink**, **signalLink**, **mainLink**, **telegramSupport**, and **signalSupport** were only being set if the authentication with the server succeeded. These values were later used throughout the program to enforce licensing checks and UI behavior.

Here’s what I learned about these variables:

- **name**: Not important.
- **expiry**: Used in the `determineExpiry` function to check if the license had expired.
- **currentMachines**: Represents the number of used machines for the license.
- **maxMachines**: The maximum number of machines allowed for the license.
- **teleLink**, **signalLink**, **signalSupport** and **mainLink**: Not important.
- **product**: This was used in a check that compared `product` with a predefined identifier (`5218ed30-0b15-4a1c-8e64-0831e8081240`).

Since these variables controlled critical functionality, manually setting them to *credible* values (*e.g., a valid future expiry date, `maxMachines = 999`*) woud allow me to bypass the need for internet connectivity or server authentication entirely.

## Modifying the Python Bytecode

To bypass the authentication checks, I had to set the specific variables mentioned earlier in the `signal` function and ensure it returned an appropriate value. The challenge, though, is that Python bytecode doesn’t let you just "push" a raw string or integer onto the stack like you might in x86 assembly with a codecave or inline value.

Instead, Python uses a **constant pool**, which is essentially a list of all the values (strings, numbers, etc.) that a function might need. These constants aren’t embedded directly in the instruction stream—instead, bytecode instructions like `LOAD_CONST` are used to reference them by index.

So to load a specific value into the stack, it has to exist in that constant pool first. This meant I had to inject my values—like a predefined `product` string or `True`/`None` values—into the constant pool of the `signal` function, and then use `LOAD_CONST` to bring them into the stack and `STORE_FAST` to set the global variables (*name, expiry, etc.*).

## Injecting Constants and Tracking Changes

To do this, I wrote a Python script that allowed me to inject the constants and print the bytecode to track my modifications. This would make it easier to visualize the changes I made, especially when using a hex editor to directly modify the bytecode.

<details open>
<summary>Script</summary>
{% highlight python %}
import marshal
import types
import dis
import binascii
import copy
import time
import importlib.util
import struct

with open("edit.pyc", "rb") as f:
    rawdata = f.read()
    f.seek(0, 0)
    header = f.read(16)  # the 16 bytes header
    code = marshal.load(f)

def find_fn_code_obj(code_obj, targetFn_name):
    if code_obj.co_name == targetFn_name:
        return code_obj
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            result = find_fn_code_obj(const, targetFn_name)
            if result:
                return result
    return None


def print_fn_consts(code_obj):
    print(f"\nConstants for '{code_obj.co_name}'")
    for i, const in enumerate(code_obj.co_consts):
        marshaled_data = marshal.dumps(const)
        hex_data = binascii.hexlify(marshaled_data).decode('utf-8')
        
        print(f"\nConst #{i}:")
        print(f"  Python value: {repr(const)}")
        print(f"  Raw bytes: {hex_data}")

def replace_consts(code_obj, new_consts):
    return types.CodeType(
        code_obj.co_argcount,
        code_obj.co_posonlyargcount,
        code_obj.co_kwonlyargcount,
        code_obj.co_nlocals,
        code_obj.co_stacksize,
        code_obj.co_flags,
        code_obj.co_code,
        tuple(new_consts),
        code_obj.co_names,
        code_obj.co_varnames,
        code_obj.co_filename,
        code_obj.co_name,
        code_obj.co_qualname if hasattr(code_obj, 'co_qualname') else code_obj.co_name,
        code_obj.co_firstlineno,
        code_obj.co_linetable if hasattr(code_obj, 'co_linetable') else code_obj.co_lnotab,
        code_obj.co_exceptiontable if hasattr(code_obj, 'co_exceptiontable') else b'',
        code_obj.co_freevars,
        code_obj.co_cellvars
    )

def inject_const_in_fn(code_obj, targetFn_name, injected_value):
    if code_obj.co_name == targetFn_name:
        new_consts = list(code_obj.co_consts) + [injected_value]
        return replace_consts(code_obj, new_consts)
    
    new_consts = []
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            const = inject_const_in_fn(const, targetFn_name, injected_value)
        new_consts.append(const)

    return replace_consts(code_obj, new_consts)

targetFn_code = find_fn_code_obj(code, 'logApi')

if targetFn_code:
    print(f"\n[Disassembly for '{targetFn_code.co_name}']")
    fn_bytecode = targetFn_code.co_code
    pos = rawdata.find(fn_bytecode)

    if pos != -1:
        print(f"Function bytecode starts at offset: 0x{pos:X}")

    dis.dis(targetFn_code)
    print_fn_consts(targetFn_code)
    

#uncomment those lines to add the constants and save the patched pyc
#modified_code = inject_const_in_fn(code, 'signal', 'Gaztoof')
#modified_code = inject_const_in_fn(modified_code, 'signal', '2030-12-12+00:00')
#modified_code = inject_const_in_fn(modified_code, 'signal', 1)
#modified_code = inject_const_in_fn(modified_code, 'signal', 10)
#modified_code = inject_const_in_fn(modified_code, 'signal', '5218ed30-0b15-4a1c-8e64-0831e8081240')
#modified_code = inject_const_in_fn(modified_code, 'signal', 'https://google.com')
#with open("edit_mod.pyc", "wb") as f:
#    f.write(header)
#    marshal.dump(modified_code, f)
#print("Wrote to edit_mod.pyc!")
{% endhighlight %}
</details>

{% highlight python %}
...
Const #31:
  Python value: 'Gaztoof'
  Raw bytes: fa2435323138656433302d306231352d346131632d386536342d303833316538303831323430

Const #32:
  Python value: '2030-12-12+00:00'
  Raw bytes: fa0a323033302d31322d3132

Const #33:
  Python value: 1
  Raw bytes: e901000000

Const #34:
  Python value: 10
  Raw bytes: e90a000000

Const #35:
  Python value: '5218ed30-0b15-4a1c-8e64-0831e8081240'
  Raw bytes: fa2435323138656433302d306231352d346131632d386536342d303833316538303831323430

Const #36:
  Python value: 'https://google.com'
  Raw bytes: fa10323033302d31322d31322b30303a3030
{% endhighlight %}

## Bypassing Server Communication with Bytecode Manipulation

The goal was clear: **force the program to use hardcoded values instead of server responses**. So now, I had to modify the **signal** function's bytecode to load the predefined constants before storing them in critical variables.

For each variable assignment, I would insert a `LOAD_CONST` instruction (*`0x64 0x00` where 0x00 is the index*) just before the corresponding `STORE_FAST`. To do so, I needed to manually modify the bytecode.

Python bytecode is made up of **opcodes** (instructions) followed by **operands** (parameters), with each opcode being a single byte. The **operand** length varies based on the **opcode**.

I also analyzed the **assembly dump** of the bytecode, where each instruction is associated with an **offset address**. By calculating the difference between the current instruction's offset and the next, I could easily determine any instruction's expected length / formatting.

- **`LOAD_CONST <const_idx>`**: Pushes a constant from the pool onto the stack.
- **`STORE_FAST <var_idx>`**: Pops the value from the stack and assigns it to a variable.

So for every variable I wanted to preset, I had to:

1. Identify its original `STORE_FAST` instruction.
2. Insert a `LOAD_CONST` instruction right before it, with the correct index pointing to my fake constant in the pool.

Instead of reconstructing the entire function, I kept only the necessary logic to:

- Load **constants** (*expiry, for example*).
- Store them in their associated **variables**.
- Return the expected value directly.

Here's a snippet of the logic I constructed manually:

<details open>
<summary>Snippet</summary>
{% highlight python %}
0000 RESUME       0
... (LOAD_CONST  31 ('Gaztoof')) 0x64 0x1F
0260 STORE_FAST  10 (name) 0x7D 0x0A
... (LOAD_CONST  32 ('2030-12-12+00:00')) 0x64 0x20
0272 STORE_FAST  11 (expiry) 0x7D 0x0B
... (LOAD_CONST  33 (1)) 0x64 0x21
0284 STORE_FAST  12 (currentMachines) 0x7D 0x0C
... (LOAD_CONST  34 (10)) 0x64 0x22
0296 STORE_FAST  13 (maxMachines) 0x7D 0x0D
... (LOAD_CONST  35 ('5218ed30-0b15-4a1c-8e64-0831e8081240')) 0x64 0x23
0308 STORE_FAST  14 (product) 0x7D 0x0E
... (LOAD_CONST  36 ('https://google.com')) 0x64 0x24
0320 STORE_FAST  15 (teleLink) 0x7D 0x0F
... (LOAD_CONST  36 ('https://google.com')) 0x64 0x24
0332 STORE_FAST  16 (signalLink) 0x7D 0x10
... (LOAD_CONST  36 ('https://google.com')) 0x64 0x24
0344 STORE_FAST  17 (mainLink) 0x7D 0x11
... (LOAD_CONST  36 ('https://google.com')) 0x64 0x24
0368 STORE_FAST  19 (signalSupport) 0x7D 0x12
0950 LOAD_GLOBAL 30 (_F)
0962 LOAD_GLOBAL 33 (NULL + str)
0974 LOAD_FAST   10 (name)
0976 PRECALL      1
0980 CALL         1
0990 LOAD_GLOBAL 33 (NULL + str)
1002 LOAD_FAST    7 (license_id)
1004 PRECALL      1
1008 CALL         1
1018 LOAD_GLOBAL 33 (NULL + str)
1030 LOAD_FAST    8 (license_key)
1032 PRECALL      1
1036 CALL         1
1046 LOAD_FAST   11 (expiry)
1048 LOAD_FAST   12 (currentMachines)
1050 LOAD_FAST   13 (maxMachines)
1052 LOAD_FAST   14 (product)
1054 LOAD_FAST   15 (teleLink)
1056 LOAD_FAST   16 (signalLink)
1058 LOAD_FAST   17 (mainLink)
1060 LOAD_FAST   18 (telegramSupport)
1062 LOAD_FAST   19 (signalSupport)
1064 BUILD_TUPLE 13
1066 RETURN_VALUE
{% endhighlight %}
</details>

So I opened the `.pyc` file in my hex editor, navigated to the start of the `signal` function’s bytecode, and began manually overwriting the instructions byte by byte. I formatted the `LOAD_CONST` and `STORE_FAST` instructions myself, making sure the constant indices matched the ones I had injected earlier.

To wrap up the function, I needed it to return a valid result. So instead of writing fresh instructions, I simply copied the relevant return-related instructions from the end of the original function and placed it right after my modified instructions.

Because I wasn’t introducing any new jumps, loops, or branches—just a straight-line sequence of instructions—I didn’t need to worry about fixing offsets or adjusting jump targets. That saved a lot of complexity, and the patched function executed cleanly.

## Removing remaining API Calls

Next, I turned my attention to removing the other functions that still communicated with the server. These included `logApi`, `collectTrackingNumberUPS`, `collectTrackingNumberFedex`, and `reverseTrackingLookup`. All of them issued HTTP requests and none returned values essential to the program’s functionality.

So I patched each of them by replacing their first instructions with a minimal stub:

{% highlight python %}
000 RESUME     0
260 LOAD_CONST 0 (None)
262 RETURN_VALUE
{% endhighlight %}

This effectively short-circuited the function. The moment it was called, it would return `None` without doing anything.

Sure, I lost the ability to fetch tracking data—but that was irrelevant to the core goal: cutting the application's link to the outside world.

## Execution

Now, all I had to do was put the final **edit.pyc** file besides the original app's `.exe` and try to execute it using Python.

After quickly fixing a few package-related errors, the application was able to run, and was fully functional without needing any internet connectivity or license.

![Running application](/assets/blogs/240425/rNoT8at.png)

# Conclusion

Sometimes, reverse engineering is less about knowing everything and more about knowing where to dig—and when to stop. You don’t always need to understand an entire system inside out; you just need to focus on the right parts, filter out the noise, and stay efficient with your time and effort.

This kind of work constantly throws unfamiliar formats, languages, and behaviors at you. You’ve got to be comfortable figuring things out on the fly, adapting quickly, and solving problems with limited context.

In this case, I didn’t need to fully decompile the binary or rebuild the whole application—I just had to extract the right bytecode, understand enough of Python’s internals to bend them to my needs, and remove the pieces that didn’t serve me.

That’s the core of it: staying sharp, staying flexible, and knowing how deep to go without getting lost in the weeds.
