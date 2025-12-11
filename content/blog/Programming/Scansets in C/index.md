---
title: "Scansets in C"
date: 2025-02-07
draft: false
description: "Scansets in C"
tags: ["Programming", "C"]
categories: ["blog"]
---
## Introduction
![Alt text](1.webp)

scanf family functions support scanset specifiers which are represented by **%[].** Inside scanset, we can specify single character or range of characters. While processing scanset, scanf will process only those characters which are part of scanset. We can define scanset by putting characters inside square brackets. Please note that the scansets are case-sensitive.

We can also use scanset by providing comma in between the character you want to add.

> **example: scanf(%s[A-Z,_,a,b,c]s,str);**

This will scan all the specified character in the scanset.
- Let us see with example. Below example will store only capital letters to character array **‘str’**, any other character will not be stored inside character array.

---

```C
/* A simple scanset example */
#include <stdio.h>

int main(void)
{
 char str[128];

 printf("Enter a string: ");
 scanf("%[A-Z]s", str);

 printf("You entered: %s\n", str);

 return 0;
}
```
> *Output:*
```bash
  [root@centos-6 C]# ./scan-set 
  Enter a string: DEADs_pro_gramming
  You entered: DEAD
```

- If first character of scanset is **‘^’**, then the specifier will stop reading after first occurrence of that character. For example, given below scanset will read all characters but stops after first occurrence of **‘o’**

```C
scanf("%[^o]s", str);
```
> *Let us see with example:*
```C
/* Another scanset example with ^ */
#include <stdio.h>

int main(void)
{
 char str[128];

 printf("Enter a string: ");
 scanf("%[^o]s", str);

 printf("You entered: %s\n", str);

 return 0;
}
```
> *Output:*
```bash
  [root@centos-6 C]# ./scan-set 
  Enter a string: http://deads programming
  You entered: http://deads pr
  [root@centos-6 C]# 
```
- Let us implement `gets()` function by using scan set. `gets()` function reads a line from stdin into the buffer pointed to by s until either a terminating newline or **EOF** found.
```C
/* implementation of gets() function using scanset */
#include <stdio.h>

int main(void)
{
 char str[128];

 printf("Enter a string with spaces: ");
 scanf("%[^\n]s", str);

 printf("You entered: %s\n", str);

 return 0;
}
```
> *Output:*
```bash
  [root@centos-6 C]# ./gets 
  Enter a string with spaces: Deads Programming
  You entered: Deads Programming
  [root@centos-6 C]# 
```

As a side note, using `gets()` may not be a good idea in general. Check below note from Linux man page.
`Never use gets()`. Because it is impossible to tell without knowing the data in advance how many characters `gets()` will read, and because `gets()` will continue to store characters past the end of the buffer, it is extremely dangerous to use. It has been used to break computer security. `Use fgets() instead.` Also see [this post](/blog/programming/gets-is-risky-to-use/).
