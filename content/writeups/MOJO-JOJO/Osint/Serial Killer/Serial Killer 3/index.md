---
title: "Serial Killer 3 - CTF Writeup"
date: 2026-02-11
draft: false
description: "Osint challenge writeup"
tags: ["Osint"]
categories: ["Writeups"]
---

**Challenge Name:** Serial Killer 3  
**Category:** Osint  
**CTF:** MOJO-JOJO  
**Description:** Good work. The account you uncovered belongs to a graphic designer involved in several projects.  
Strangely, none of these projects seem easy to trace. Almost as if they were meant to disappear.  
Where did these works surface? And what do they reveal?  
Keep digging.  
Flag Format: MOJO-JOJO{City_NN}

---

## Challenge Description

> "None of these projects seem easy to trace. Almost as if they were meant to disappear."

The challenge hints at deleted or hidden content that needs to be uncovered through OSINT techniques.

## Solution

### Step 1: Finding Deleted Posts

Reading the description carefully, it was clear that the posts had been deleted. To recover deleted web content, I turned to [archive.ph](https://archive.ph/) to search for archived snapshots of the target page.

![Screenshot: Archive.is search](1.png)

### Step 2: Discovering the GitHub Repository

Success! The archived snapshot revealed a deleted post that contained a link to a **GitHub repository**.

![Screenshot: Deleted post with GitHub link](2.png)

### Step 3: Decoding the Base64 String

Diving into the repository, I found a `.txt` file containing a **Base64-encoded string**.

![Screenshot: Base64 string in repository](3.png)

Using [CyberChef](https://gchq.github.io/CyberChef/), I decoded the string and retrieved the missing **two-digit number: 22**.

![Screenshot: CyberChef decoding](4.png)

### Step 4: Finding the City

We still needed to identify the city. I explored the repository further and checked the **commit history**.

![Screenshot: Commit history](5.png)

In one of the commits, the city was finally revealed: **Bizerte**.

![Screenshot: Commit revealing city](6.png)

## Flag

```
MOJO-JOJO{Bizerte_22}
```

