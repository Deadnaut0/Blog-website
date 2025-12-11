---
title: "gets() is risky to use!"
date: 2025-02-06
draft: false
description: "the risk of gets usage"
tags: ["Programming", "C"]
categories: ["blog"]
---
![Alt text](feature.webp "BUFFER OVERFLOW")

Consider the below program.

```C
void read()
{
   char str[20];
   gets(str);
   printf("%s", str);
   return;
}
```
The code looks simple, it reads string from standard input and prints the entered string, but it suffers from `Buffer Overflow` as **gets()** doesn’t do any array bound testing. **gets()** keeps on reading until it sees a newline character.
To avoid Buffer Overflow, `fgets()` should be used instead of **gets()** as **fgets()** makes sure that not more than `MAX_LIMIT` characters are read.
```C
#define MAX_LIMIT 20
void read()
{
   char str[MAX_LIMIT];
   fgets(str, MAX_LIMIT, stdin);
   printf("%s", str);
 
   getchar();
   return;
}
```
***NOTE:*** `fgets()` stores the `‘\n’` character if it is read, so removing that has to be done explicitly by the programmer. It is hence, generally advised that your str can store at least `(MAX_LIMIT + 1)` characters if your intention is to keep the newline character. This is done so there is enough space for the null terminating character `‘\0’` to be added at the end of the string.

- If keeping the newline character is not intended, then one can simply do the following:
```C
int len = strlen(str);

// Remove the '\n' character and replace it with '\0'
str[len - 1] = '\0';
```
