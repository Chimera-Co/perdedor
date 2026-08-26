# PERDEDOR Learning Guide — Volume 1: Foundations
### From "I have never programmed before" to "I understand every concept behind PERDEDOR"

---

## How to use this document

This is Volume 1 of a two-volume set. It is written so that a person with
**zero prior knowledge** of programming, operating systems, computer
hardware, virtualization, or cybersecurity can read it start to finish and
come out the other side understanding every single concept that the PERDEDOR
project touches. Volume 2 (`BUILD_GUIDE_VOL2_PERDEDOR_FROM_SCRATCH.md`) then
takes that foundation and walks through the *actual PERDEDOR source code*, line
by line, so that after reading both volumes you could rebuild the entire
project yourself from an empty folder.

You do not need any other book, course, video, or website. Every piece of
jargon used anywhere in this document is defined the first time it is used,
and again in the glossary at the end. If you ever read a term you don't
recognize, jump to the glossary (Chapter 21) — it is alphabetical.

**How the chapters build on each other:** later chapters assume you have
read the earlier ones. Chapter 10 (Computer Architecture) assumes you
understand Chapter 1 (What Is a Computer). Chapter 12 (Virtualization)
assumes you understand Chapter 10 and Chapter 11 (Operating Systems
Internals). If a chapter feels confusing, it is worth going back one or two
chapters rather than pushing forward.

**A note on depth:** this document goes deeper than a typical "intro to
programming" tutorial on purpose. PERDEDOR is a security tool that pokes at the
lowest levels of a computer — CPU instructions, firmware tables, kernel
modules — so a shallow explanation would leave you unable to understand why
the tool works. Take your time. There is no exam and no deadline.

### Table of Contents

1. What Is a Computer? (bits, bytes, memory, storage, the CPU)
2. What Is an Operating System?
3. Programming Fundamentals (language-agnostic concepts)
4. Python Deep Dive
5. The Command Line and Shell Scripting (Bash)
6. PowerShell and .NET Deep Dive
7. C Programming Basics
8. Git and Version Control
9. JSON and Schemas
10. Computer Architecture Deep Dive (CPU registers, CPUID, RDTSC, x86 vs ARM)
11. Operating System Internals (Linux, Windows, Android)
12. Virtualization Deep Dive (hypervisors, KVM, QEMU, VirtIO, SMBIOS)
13. Containers Deep Dive (Docker, namespaces, cgroups)
14. Malware Analysis and Sandboxes
15. Malware Evasion Techniques (the four-category model)
16. Reverse Engineering and Debugging Basics
17. The Prior Art: Pafish, al-khaser, and VMAware
18. Security Engineering Practices Used in This Project
19. Networking Basics Relevant to PERDEDOR
20. Putting It All Together: How PERDEDOR's Design Falls Out of These Ideas
21. Complete Glossary
22. Suggested Study Plan

---

## Chapter 1: What Is a Computer?

### 1.1 The big picture

A computer is a machine that follows instructions. That's it — that's the
whole idea, and everything else in this document is detail on top of that
one sentence. A computer doesn't "think." It reads a list of very simple
instructions (like "add these two numbers" or "copy this piece of data from
here to there") one at a time, extremely fast, and does exactly what each
instruction says.

Every program you have ever used — a web browser, a game, a word processor,
and every tool inside PERDEDOR — is, underneath, nothing but a very long list
of these simple instructions.

### 1.2 Bits and bytes

Computers store and move information as **bits**. A bit is the smallest
possible unit of information: it can be either `0` or `1`, and nothing else.
Physically, inside real hardware, a bit is usually represented by whether a
tiny transistor (an electronic switch) is "on" or "off", or whether a tiny
spot on a disk is magnetized one way or the other. You never need to touch
this physical level yourself — but it's worth knowing that ultimately,
*everything* a computer does — every photo, every piece of text, every
sound, every program — is stored as a giant sequence of `0`s and `1`s.

A single bit isn't very useful on its own (it can only represent two
possible states), so bits are grouped together. The most common grouping is
a **byte**, which is 8 bits. Since each bit can be `0` or `1`, a byte can
represent 2×2×2×2×2×2×2×2 = 256 different values (0 through 255).

Bytes are, in turn, grouped into larger units:
- **Kilobyte (KB)** ≈ 1,000 bytes (technically 1,024 in most computing
  contexts, because computers count in powers of 2, not powers of 10 — you
  will see both 1000-based and 1024-based versions used; PERDEDOR's code uses
  1024-based units, often written **KiB**, **MiB**, **GiB** to be precise
  about this)
- **Megabyte (MB / MiB)** ≈ 1,000 KB / 1,024 KiB
- **Gigabyte (GB / GiB)** ≈ 1,000 MB / 1,024 MiB — a typical laptop has a
  handful to a few dozen GiB of RAM, and a hundred or more GiB of storage
- **Terabyte (TB / TiB)** ≈ 1,000 GB / 1,024 GiB

You'll see these units throughout PERDEDOR's code — for example, one of its
checks flags a virtual machine that has suspiciously little RAM (`<= 4
GiB`) or a suspiciously small disk (`<= 60 GiB`), because real, everyday
laptops and desktops in current use tend to have more than that, while
disposable sandbox VMs are often provisioned minimally to save cost.

### 1.3 Binary, decimal, and hexadecimal

Humans normally count in **decimal** (base 10): the digits 0-9, and when you
run out you carry over into the next column (9, then 10). Computers
naturally count in **binary** (base 2): only the digits 0 and 1. The number
"five" in decimal is `5`; in binary it's `101` (which means
1×4 + 0×2 + 1×1 = 5).

Binary numbers get long and hard for humans to read quickly (the number 255
is `11111111` in binary — eight digits for a fairly small number). So
programmers very often use a third number system: **hexadecimal** (base
16), often just called "hex." Hex uses sixteen digits: `0123456789abcdef`
(where `a` through `f` stand in for the values 10 through 15). Each single
hex digit represents exactly 4 bits, so two hex digits represent exactly one
byte (8 bits) — a nice, compact match. The number 255 (which is `11111111`
in binary) is simply `ff` in hex. In code, hex numbers are usually written
with a `0x` prefix, e.g. `0xff` or `0x40000000`.

You will see hex numbers constantly in PERDEDOR's code, especially in the
Linux and Windows agents' CPU-related checks — for example, the code asks
the CPU for "CPUID leaf `0x40000000`" (explained fully in Chapter 10). That
`0x40000000` is just a specific, agreed-upon number that both the CPU and
the hypervisor understand as "give me the hypervisor's identity string."
Hex is used instead of decimal here purely because it lines up so cleanly
with bytes and makes patterns in the numbers easier for humans to spot.

**Practical conversion tip:** you will never need to hand-convert between
these systems while working with PERDEDOR — Python and PowerShell both do it
for you (e.g. Python's `hex(255)` returns `'0xff'`, and `int('ff', 16)`
returns `255`). What matters is recognizing *that* a number is in hex (the
`0x` prefix) and having a rough mental model of why it's used.

### 1.4 Memory (RAM) vs. storage (disk)

A computer has (at least) two very different places to keep data:

- **RAM (Random Access Memory)**, often just called "memory," is
  extremely fast but *temporary* — everything in RAM disappears the moment
  the computer loses power or restarts. RAM holds the data a running
  program is actively working with right now: variables, open files'
  contents, etc.
- **Storage** (a hard disk drive/HDD, or more commonly today a solid-state
  drive/SSD) is much slower than RAM but *permanent* — data written to
  storage survives a restart. Storage holds your files, installed programs,
  and the operating system itself, waiting to be loaded into RAM when
  needed.

This distinction matters directly to PERDEDOR: one of its Linux checks reads
`/proc/meminfo` to find the total amount of RAM (a low amount is a sandbox
tell), and a different check reads `/sys/block/*/size` to find the size of
the *disk* (a small disk is a separate, independent sandbox tell). They are
measuring two different physical resources for two independent reasons.

### 1.5 The CPU (Central Processing Unit)

The CPU is the part of the computer that actually *executes* instructions —
it's the "brain," although that metaphor undersells how mechanical and
non-intelligent it actually is. The CPU repeatedly does a very simple loop,
often called the **fetch-decode-execute cycle**:

1. **Fetch**: get the next instruction from memory.
2. **Decode**: figure out what that instruction means (e.g. "add two
   numbers," "compare two numbers," "jump to a different instruction").
3. **Execute**: actually do it.
4. Repeat, forever, for as long as the computer is running.

Modern CPUs do this *billions* of times per second (a "3 GHz" CPU
completes roughly 3 billion of these cycles every second) and have
multiple **cores** — essentially multiple independent CPUs bundled onto one
chip, each able to run its own instruction stream at the same time. This is
why "core count" is meaningful, and why PERDEDOR has a "low core count" check:
a virtual machine given only 1-2 cores when a real user's everyday computer
usually has 4, 6, 8, or more is a plausible sandbox tell.

Inside the CPU, there is a small number of extremely fast storage slots
called **registers**. Unlike RAM (which can hold gigabytes but is
relatively slow to access) or storage (even slower, but essentially
unlimited), registers hold just a handful of bytes each, but the CPU can
read and write them in a single cycle. Registers are where the CPU keeps
the numbers it is actively working with right now. You will see specific
register names — `EAX`, `EBX`, `ECX`, `EDX` — throughout PERDEDOR's Linux and
Windows agents. Chapter 10 explains exactly what these are and why PERDEDOR
cares about them.

### 1.6 Peripherals and buses

A computer is not just a CPU and memory — it's connected to many other
components: a graphics card, a network card, storage drives, USB devices,
and so on. These are called **peripherals** or **devices**, and they are
connected to the CPU/memory over a shared communication pathway called a
**bus**. The most common bus standard for internal components today is
called **PCI** (Peripheral Component Interconnect) or its modern variant
**PCIe** (PCI Express). Every device on a PCI bus identifies itself with a
**vendor ID** and a **device ID** — two short hexadecimal numbers that say
"I am a network card made by company X, model Y." Operating systems use
these IDs to automatically find and load the right driver software for each
device.

This matters to PERDEDOR directly: one of its Linux checks
(`linux.env.pci_virtio_devices`) reads the vendor ID of every PCI device
present in the system and checks it against a list of vendor IDs that are
known to belong to *virtual*, hypervisor-provided devices (rather than real
physical hardware) — for example, vendor ID `0x1af4` belongs to "Red Hat /
virtio," a family of devices that only exist inside virtual machines. If a
`0x1af4` device shows up, that's very strong evidence the machine is
virtualized. Chapter 12 goes into this in much more depth.

### 1.7 Firmware, BIOS, and UEFI

Before an operating system loads, a much smaller, much more primitive
program runs first: the **firmware**, historically called the **BIOS**
(Basic Input/Output System) and, on modern hardware, replaced by **UEFI**
(Unified Extensible Firmware Interface). Firmware lives in a small chip on
the motherboard (the main circuit board a computer's components plug into)
and is responsible for the very first steps of turning a computer on:
checking that basic hardware is present and working, and then handing
control over to the operating system's own startup code (a process called
**booting**).

Firmware carries identifying information about the hardware — the
motherboard manufacturer's name, the BIOS version, the system's serial
number, and so on. This information is organized into a standardized data
structure called **SMBIOS** (System Management BIOS), also loosely called
**DMI** (Desktop Management Interface) data. When you run virtualization
software, the hypervisor has to *invent* fake SMBIOS/DMI data for the
virtual machine, because there's no real physical motherboard to report on
— and by default, many hypervisors fill in that fake data with strings
that literally say things like `"QEMU"`, `"innotek GmbH"` (the original
company behind VirtualBox), or `"VMware, Inc."`. This is one of the single
richest sources of "this is a virtual machine" evidence, and PERDEDOR checks
it extensively on both Linux and Windows (Chapter 12 explains exactly how).

---

## Chapter 2: What Is an Operating System?

### 2.1 Why you need one

The CPU only understands extremely low-level instructions. If every program
had to talk directly to the CPU, directly to the disk, directly to the
network card, etc., every single program would need to reinvent an enormous
amount of complex, hardware-specific code, and two programs running "at the
same time" would constantly fight over the same hardware.

An **operating system (OS)** is the layer of software that sits between
raw hardware and the programs (**applications**) you actually want to run.
It manages hardware on every program's behalf, and provides a common,
simplified way for programs to ask for things ("read this file," "send this
network packet," "show this on screen"). Windows, Linux, macOS, and Android
are all operating systems.

### 2.2 The kernel vs. userspace

Every general-purpose OS has a core piece called the **kernel**. The
kernel is the part of the OS that runs with full, unrestricted access to
the hardware. It manages memory, schedules which program's instructions the
CPU executes at any given moment, talks to hardware devices via **drivers**
(small programs specific to one piece of hardware), and enforces the rules
that keep programs from interfering with each other.

Everything else — your web browser, your text editor, even most of the
graphical desktop you see — runs in **userspace** (sometimes "user mode"),
a more restricted execution mode where a program *cannot* directly touch
hardware or another program's memory. Instead, userspace programs make
**system calls** ("syscalls") — formal requests to the kernel, like "please
read 100 bytes from this file" — and the kernel decides whether to grant
the request and does the actual hardware-level work.

This separation exists for safety and stability: if a userspace program
crashes or misbehaves, the kernel can shut it down without the whole
computer crashing. If the kernel itself crashes, the whole system typically
goes down (a "kernel panic" on Linux/macOS, a "blue screen" on Windows).

This distinction matters to PERDEDOR because many of its checks specifically
read files the *kernel* exposes about itself and the hardware — Chapter 11
covers Linux's `/proc` and `/sys` virtual filesystems, which are exactly
this: windows into kernel-held information, readable from ordinary
userspace code without needing special privileges.

### 2.3 Processes

A **process** is a running instance of a program. When you double-click an
application or type a command to run one, the OS creates a new process for
it: it allocates that process its own private chunk of memory, sets up
bookkeeping so the kernel can schedule its instructions to run on a CPU
core, and tracks it until it exits. You can have many processes running
"the same program" at once (e.g. two browser windows are usually two
separate processes, or groups of related processes), and each is isolated
from the others' memory by default.

Every process has a numeric identifier, the **PID (Process ID)**, and the
OS keeps a list of every currently-running process. PERDEDOR reads this list
directly in several checks — for example, to see whether known
analysis/debugging tools (like Wireshark, a network traffic inspector, or
gdb, a debugger) are currently running, since their presence alone is a
strong signal that "a human analyst is actively watching this machine,"
which is itself a sandbox-detection technique malware authors use (Chapter
15 covers this "design-specific" detection category in depth).

### 2.4 Files, directories, and paths

An OS organizes persistent storage into **files** (a named sequence of
bytes) arranged in **directories** ("folders," which can contain files and
other directories), forming a tree structure. The location of a file within
this tree is called its **path**.

Linux/macOS paths use forward slashes and start from a single root, written
`/`: for example `/home/alice/notes.txt`. Windows paths use backslashes and
start from a drive letter: `C:\Users\Alice\notes.txt`. This is a small but
constant source of friction when writing software that has to run on both
— and it's part of why PERDEDOR has entirely separate agents for Windows,
Linux, and Android rather than one shared codebase for all three.

### 2.5 Permissions

Files, directories, and other OS resources have **permissions** attached —
rules about which users and processes are allowed to read, write, or
execute them. On Linux, permissions are commonly shown as a string like
`rwxr-xr--` (read/write/execute, for the file's owner / owning group /
everyone else). Some operations require **elevated privileges** — on
Linux/macOS this is "root" access (via a command called `sudo`), on Windows
it's "Administrator" access ("running as admin" / an elevated prompt).

PERDEDOR's checks are deliberately written to *never require* elevated
privileges — they only read information any ordinary logged-in user can
already see. This matters because PERDEDOR's Windows agent README explicitly
recommends running it "from an elevated prompt" for the most complete
results, but even without elevation, checks degrade gracefully (reporting
`error` with a clear reason) rather than crashing.

### 2.6 Environment variables

Every process is started with a set of **environment variables** — simple
named text values inherited from whatever started it (usually your shell,
covered in Chapter 5). They're used for lightweight configuration: for
example, on Linux, the `USER` environment variable holds your username;
on Windows, `%LOCALAPPDATA%` holds the path to a per-user folder for
application data. PERDEDOR reads several of these directly — for instance, its
Linux "suspicious username" check reads the `USER` (or `LOGNAME`)
environment variable and compares it against a list of implausible names
like `"sandbox"` or `"test"`.

### 2.7 Services and daemons

Many programs are designed to run continuously in the background, without
a visible window, providing some ongoing capability rather than doing one
task and exiting. On Linux these are usually called **daemons**; on Windows
they're called **services**. Virtualization guest-integration tools
(explained fully in Chapter 12) are almost always installed as a
background service/daemon — for example, VirtualBox installs a Windows
service called `VBoxService`. PERDEDOR's Windows agent literally asks Windows
"is there a service named `VBoxService` installed?" as one of its checks —
if the answer is yes, this machine is (or very recently was) a VirtualBox
guest, full stop, regardless of anything else.

## Chapter 3: Programming Fundamentals (Language-Agnostic Concepts)

This chapter explains the concepts that exist in *every* programming
language before Chapter 4 shows you what they look like specifically in
Python (the language most of PERDEDOR is written in). If you already know how
to program in any language, skim this chapter — you likely just need the
vocabulary refresher.

### 3.1 What is "code"?

**Source code** (or just "code") is human-readable text, written in a
**programming language**, that describes a sequence of instructions. A
program called a **compiler** or **interpreter** converts that text into
something the CPU can actually execute (or executes it step-by-step
on-the-fly). You, as a programmer, write the text; the computer does the
rest.

- A **compiled** language (like C, covered in Chapter 7) is translated
  *entirely* into raw CPU instructions (a "binary" or "executable") ahead
  of time, by a compiler, before you ever run the program.
- An **interpreted** language (like Python and PowerShell, covered in
  Chapters 4 and 6) is read and executed line-by-line, on the fly, by
  another program (the **interpreter**) every time you run it. This is
  usually slower than compiled code but much faster to develop and test
  with, since there's no separate "build" step.

PERDEDOR uses both: its Linux and Android agents, its shared library, and its
command-line tool are all Python (interpreted); its Windows agent is
PowerShell (also interpreted, running on top of a compiled runtime called
.NET); and its Linux agent additionally includes one small piece of C
(compiled) for the handful of things Python genuinely cannot do on its own.
Chapter 7 explains exactly why that C piece exists.

### 3.2 Variables and data types

A **variable** is a named storage location that holds a value, which can
change ("vary") over the life of the program. Every value has a **data
type** that determines what operations make sense on it and how much memory
it takes. The universally common basic types are:

- **Integer** (`int`): a whole number, positive or negative, with no
  fractional part (`5`, `-12`, `0`).
- **Floating-point number** (`float`): a number that can have a fractional
  part (`3.14`, `-0.5`). Called "floating-point" because of how the
  decimal point's position is stored internally (a detail you never need
  to worry about day-to-day).
- **String** (`str`): a sequence of text characters (`"hello"`,
  `"192.168.1.1"`). Always wrapped in quotes in code, so the language can
  tell text apart from other code.
- **Boolean** (`bool`): exactly one of two values, `True` or `False`
  (called "boolean" after George Boole, a 19th-century mathematician).
  Booleans are what "yes/no" questions in code resolve to — e.g. "is this
  number greater than 10?" is a boolean question.
- **None / null**: a special value meaning "no value at all" — distinct
  from `0`, `False`, or an empty string. Python spells this `None`;
  PowerShell/.NET spell it `$null`; many languages spell it `null`. PERDEDOR
  uses this constantly: for example, when a check tries to read a file that
  doesn't exist, the function that reads it returns `None` rather than an
  empty string, so the calling code can tell "the file was empty" apart
  from "the file could not be read at all" — a distinction that turned out
  to matter for a real bug PERDEDOR hit during development (Volume 2 covers
  this bug as a case study).

### 3.3 Collections

Beyond single values, languages provide ways to group multiple values
together:

- A **list** (also called an "array" in many languages) is an ordered
  sequence of values, e.g. `[1, 2, 3]` or `["qemu", "vbox", "vmware"]`.
  You can access an element by its position (**index**) — the first
  element is at index `0`, not `1` (this is called **zero-based
  indexing**, and it trips up nearly every beginner at least once. It's
  zero-based because the index is really "how many elements to skip from
  the start," and skipping zero elements gets you the first one).
- A **tuple** is like a list, but *immutable* — once created, it cannot be
  changed. Chapter 4 explains why PERDEDOR specifically prefers tuples over
  lists in several places, tying back to the "immutability" principle
  this codebase follows throughout.
- A **dictionary** (called a "hash map," "hash table," or "associative
  array" in other languages) is a collection of **key-value pairs**: each
  value is looked up by a unique key rather than by position, e.g.
  `{"qemu": "QEMU/KVM", "vbox": "VirtualBox"}` lets you look up the
  human-readable vendor name for a short signature string. PERDEDOR's
  signature lists (Chapters 12 and 15 cover what these signatures actually
  are) are almost all dictionaries or tuples.
- A **set** is an unordered collection of *unique* values — like a list
  but with duplicates automatically removed and no guaranteed order.

### 3.4 Control flow

By default, a program executes its instructions top to bottom, one after
another. **Control flow** statements change that default order:

- **`if` / `else`** ("conditionals"): run one block of code if some
  condition is true, and a different block otherwise. E.g. "if the CPU
  vendor string matches a known hypervisor, mark this check as detected;
  otherwise mark it clean."
- **Loops** (`for`, `while`): repeat a block of code multiple times. A
  `for` loop typically repeats once per item in a collection ("for each
  PCI device in the list of devices, check its vendor ID"). A `while` loop
  repeats as long as some condition stays true.
- **Functions**: a named, reusable block of code that can be *called*
  (invoked) from elsewhere, optionally taking input values (**parameters**
  / **arguments**) and optionally producing an output value (a **return
  value**). Functions are the single most important tool for organizing
  code, because they let you write a piece of logic once and reuse it
  everywhere it's needed, and give that logic a memorable name. Nearly
  every "check" in PERDEDOR (e.g. `check_cpu_brand_string`) is a function:
  a self-contained unit that runs one specific test and returns one
  specific result.
- **Exceptions / error handling**: when something goes wrong inside a
  function (a file doesn't exist, a network request times out, a value is
  the wrong type), most modern languages let code **raise** (or "throw") an
  **exception** — a special signal that immediately stops normal execution
  and jumps to the nearest place in the code that has declared it knows how
  to **catch** (handle) that kind of problem, using a `try` / `except` (or
  `try` / `catch`) block. If nothing catches it, the exception propagates
  all the way up and crashes the program with an error message. PERDEDOR's
  code uses `try`/`except` heavily, precisely because it's constantly doing
  things that might fail for reasons outside its control (a file that
  doesn't exist on this particular OS, a command that isn't installed, a
  device that's unreachable) — and the whole design philosophy of the tool
  is that one failed check should never crash the rest of the scan (more on
  this in Chapter 18).

### 3.5 Objects, classes, and structuring data

Most modern languages let you define your own custom data types, bundling
several related values together under one name, called a **class** (and an
individual instance of a class is called an **object**). For example, you
might define a class called `Finding` that bundles together "which check
this is," "did it detect something," "how severe is that," and "what
evidence backs it up" — instead of passing those four-plus separate values
around individually everywhere in the code. This is exactly what PERDEDOR does
— its `Finding` class (Chapter 4 of Volume 2 covers it in full) is the
single most important data structure in the whole project; almost
everything else in the codebase exists to create, collect, or display
`Finding` objects.

A specific, restricted style of class that only exists to hold data (with
no complicated behavior attached) is often called a **data class**,
**record**, or **DTO** ("Data Transfer Object"). Python has a built-in
`@dataclass` feature for exactly this, which PERDEDOR uses for `Finding` and
`PlatformReport`. Chapter 4 covers `@dataclass` syntax directly.

### 3.6 Modules and packages

As a program grows, it's split into multiple files, each holding related
code — called **modules**. Multiple related modules are bundled together
into a **package**. Other code can then **import** a module or package to
use the functions/classes it defines, without needing to know or care how
they're implemented internally — only what they do. This is one of the
most important ideas in all of software engineering: it lets you build
complex systems out of smaller, independently-understandable pieces, and
it's the entire reason PERDEDOR's repository is organized the way it is (a
shared `perdedor_common` package, three separate per-platform agent packages,
and a CLI package that imports from all of them — Volume 2, Chapter 2 gives
the full tour).

### 3.7 Comments

A **comment** is text in source code that is ignored by the
compiler/interpreter entirely — it exists purely for human readers.
Different languages use different symbols to mark a comment: Python and
Bash use `#`, PowerShell uses `#` (single-line) or `<# ... #>` (multi-line
block), C uses `//` (single-line) or `/* ... */` (multi-line). Comments are
for explaining *why* code does something non-obvious, not *what* it does
(well-named code should make the "what" obvious on its own) — this project
in particular follows that discipline strictly, and Volume 2 will point out
specific comments in PERDEDOR's code that exist because they document a real
bug, a subtle platform difference, or a design tradeoff that wouldn't be
obvious from the code alone.

### 3.8 Immutability — a concept this project cares about a lot

A value is **mutable** if it can be changed in place after creation, and
**immutable** if it cannot — any "change" to an immutable value actually
produces a brand new value, leaving the original untouched. Numbers and
strings are immutable in most languages by default; lists/dictionaries are
usually mutable by default.

Why would you *want* immutability? Because mutable shared data is one of
the most common sources of hard-to-find bugs in software: if two different
parts of a program both hold a reference to the same mutable object, and
one of them changes it, the other part is silently affected too — often in
a way that's very hard to trace back to its cause. Immutable data sidesteps
this entire class of bug: if nothing can be changed after creation, nothing
can be silently changed out from under you.

PERDEDOR deliberately builds its two most important data structures
(`Finding` and `PlatformReport`) as **frozen** (immutable) — attempting to
modify one after creation raises an error rather than silently succeeding.
Chapter 4 shows exactly how Python enables this (`@dataclass(frozen=True)`)
and Volume 2 explains where this choice actually mattered in practice.

## Chapter 4: Python Deep Dive

Python is the language used for PERDEDOR's shared library (`perdedor_common`),
its Linux agent, its Android agent, and its command-line tool. This chapter
teaches Python from scratch, in enough depth to read (and eventually write)
every `.py` file in the project.

### 4.1 Why Python, and how it runs

Python is an interpreted, general-purpose language known for readable
syntax and a huge standard library (a large set of built-in functionality
you get for free, without installing anything extra). You write `.py` text
files, and run them with the `python` (or `python3`) command, which reads
and executes them.

PERDEDOR deliberately restricts itself to Python's **standard library only**
for its Linux and Android agents (no third-party packages required to run
them) — this is a design choice, not an accident: it means the agent can be
copied onto a fresh machine and just work, without needing an internet
connection to download dependencies first. You'll see this reflected in the
Linux agent module's own docstring, which calls it a "pure-stdlib" agent.

### 4.2 Basic syntax

Python uses **indentation** (leading whitespace) to mark code blocks,
instead of curly braces `{}` (used by C, PowerShell/C#, JavaScript, and
many others). This is not just a style choice — it's mandatory and
meaningful:

```python
def greet(name):
    if name:
        print(f"Hello, {name}!")
    else:
        print("Hello, stranger!")
```

Everything indented under `def greet(name):` is *inside* that function.
Everything indented under `if name:` is *inside* that branch. Get the
indentation wrong and either Python refuses to run the code (`IndentationError`)
or, worse, the code runs but does something different than you intended.
By strong convention (and by the `black` auto-formatter tool this project
uses, covered in Chapter 18), Python code uses 4 spaces per indentation
level, never tabs.

A colon `:` always precedes an indented block — after `if`, `else`, `for`,
`while`, `def` (function definitions), `class` (class definitions), `try`,
`except`, and a few others.

### 4.3 Defining and calling functions

```python
def add(a, b):
    return a + b

result = add(3, 4)   # result is now 7
```

`def` starts a function definition. `add` is the function's name. `(a, b)`
are its **parameters** — names for the values it expects to be given.
`return` specifies the value the function produces when called; a function
with no `return` statement implicitly returns `None`.

Python supports **type hints** (also called type annotations) — optional
notes in the code about what type each parameter and return value is
expected to be:

```python
def add(a: int, b: int) -> int:
    return a + b
```

Type hints are **not enforced at runtime** by Python itself — they're
purely documentation for humans and for separate tools (like `mypy`) that
can check your code for type mistakes before you ever run it. PERDEDOR's
coding-style rules require type annotations on every function signature,
and you will see them on essentially every function in the codebase — they
make it possible to know, at a glance, exactly what a function expects and
returns, without having to read its entire body.

More advanced type hints you'll see throughout PERDEDOR:
- `str | None` means "either a string, or `None`" (this is Python's
  "union type" syntax, read as "str or None"). It's used constantly for
  values that are legitimately allowed to be absent — e.g. an Android
  device serial number is `str | None` because you might not have one
  (only one device attached, so none needs specifying).
- `list[Finding]` means "a list where every element is a `Finding`
  object."
- `tuple[str, ...]` means "a tuple of strings, of any length" (the `...`
  is literal Python syntax here, meaning "zero or more of the preceding
  type").
- `dict[str, str]` means "a dictionary where both the keys and the values
  are strings."

### 4.4 Strings in depth

Strings are written with either single (`'...'`) or double (`"..."`)
quotes — Python treats them identically, but this project's `black`
formatter standardizes on double quotes throughout. A few string features
used heavily in PERDEDOR:

- **f-strings** (formatted string literals): put an `f` right before the
  opening quote, and then any `{expression}` inside the string is replaced
  with that expression's value, computed live:
  ```python
  count = 3
  print(f"{count} devices found")   # prints: 3 devices found
  ```
  You will see f-strings on nearly every line of PERDEDOR that builds a
  human-readable description or evidence string, e.g.
  `f"{value!r}" + (f" (matched {hit!r})" if hit else "")`. The `!r` suffix
  inside an f-string means "use `repr()` instead of `str()`" — `repr()`
  produces a form meant for *debugging* (e.g. it wraps strings in quotes
  and escapes special characters), which is exactly what you want when
  showing raw evidence data, since it makes it unambiguous exactly what
  characters were actually present (including invisible ones).
- **String methods**: strings have many built-in operations you call with
  dot-notation, e.g. `"QEMU".lower()` returns `"qemu"`; `"a,b,c".split(",")`
  returns the list `["a", "b", "c"]`; `text.strip()` removes leading/
  trailing whitespace; `"vbox" in "innotek vbox device"` checks whether one
  string contains another (this `in` check, used on lowercased text, is the
  single most common pattern in PERDEDOR's entire signature-matching logic —
  Chapter 15 covers what's actually being matched and why).
- **Byte strings** (`bytes`, written `b"..."`): a sequence of raw bytes
  rather than Unicode text characters — used when working with genuinely
  binary data (like CPU register contents or a raw firmware table) before
  it's been decoded into human-readable text. PERDEDOR's CPU-vendor-string
  decoding logic works directly with `bytes` objects, converting raw
  register values into byte sequences and then decoding those into ASCII
  text (Chapter 10 explains exactly what's being decoded and why register
  *order* matters so much there).

### 4.5 `None` and truthiness

Python treats several values as "falsy" in a boolean context (like an
`if` condition) even though they're not literally `False`: `None`, `0`,
`0.0`, empty strings `""`, empty lists `[]`, empty dicts `{}`, and empty
tuples `()` are all falsy; essentially everything else is "truthy." This
means `if value:` is a common, idiomatic shorthand for "if value is not
None and not empty." PERDEDOR uses this constantly, e.g.
`if match:` after a signature lookup that returns either a matched string
or `None`.

A very important, PERDEDOR-specific distinction: several functions
deliberately return `None` to mean "I could not determine this" (an
*error* condition) as opposed to returning an empty value to mean "I
checked, and there was genuinely nothing there" (a *clean* result). Getting
this distinction backwards was a real bug caught during PERDEDOR's
development (Volume 2 covers it as a named case study) — it's one of the
most important lessons in the entire codebase: **absence of data is not
automatically a "clean" result.**

### 4.6 Lists, tuples, dicts, and comprehensions

```python
signatures = ("qemu", "vbox", "vmware")             # a tuple (immutable)
counts = [1, 2, 3]                                    # a list (mutable)
vendors = {"qemu": "QEMU/KVM", "vbox": "VirtualBox"}  # a dict
```

A **list/dict/set comprehension** is compact syntax for building a new
collection by transforming or filtering an existing one, in a single
expression:

```python
hits = [tool for tool in ANALYSIS_TOOL_PROCESS_NAMES if tool in running]
```

Read this right-to-left-ish: "for each `tool` in `ANALYSIS_TOOL_PROCESS_NAMES`,
if `tool` is in `running`, include it" — producing a new list of just the
tools that are actually running. This single line replaces what would
otherwise be a multi-line explicit loop with an empty list, a `for`, an
`if`, and an `.append()` call — comprehensions are extremely idiomatic
Python and appear throughout PERDEDOR's signature-matching checks.

Dictionaries have a `.get(key, default)` method that looks up a key and
returns a fallback value instead of raising an error if the key isn't
present:
```python
known = CPUID_HYPERVISOR_VENDORS.get(vendor)   # None if vendor isn't a known key
```

### 4.7 Classes and dataclasses

A plain Python class:

```python
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
```

`__init__` is a special method (Python calls these **dunder methods**,
short for "double underscore," because their names start and end with
`__`) that runs automatically when you create a new instance:
`p = Point(3, 4)`. `self` refers to the specific instance being created or
operated on — it's always the first parameter of a regular method, and
Python passes it automatically; you never provide it yourself when calling.

Writing `__init__` by hand for every simple data-holding class gets
repetitive fast, so Python provides the `@dataclass` **decorator** (a
decorator is a special marker, prefixed with `@`, placed above a
function/class definition, that wraps it with extra behavior) to generate
this boilerplate automatically:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    id: str
    category: Category
    platform: Platform
    status: Status
```

`@dataclass` auto-generates `__init__` (so you can write `Finding(id=...,
category=..., ...)`), plus sensible default implementations of equality
comparison and a readable string representation, purely from the list of
fields you declare. `frozen=True` is the specific flag that makes
instances **immutable** after creation — attempting `some_finding.id =
"new"` after the fact raises an error. This is exactly the
"immutability" principle from Chapter 3.8, applied concretely: PERDEDOR's
`Finding` and `PlatformReport` classes are both frozen dataclasses.

### 4.8 Enums

An **enum** (enumeration) defines a fixed, named set of possible values —
useful when a value should only ever be one of a small, known list of
options, and you want that restriction enforced by the type system rather
than by convention alone:

```python
from enum import Enum

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

PERDEDOR defines four enums this way — `Category`, `Platform`, `Status`, and
`Severity` — precisely because each of these concepts really is a small,
fixed, closed set of options (there are exactly four detection categories,
exactly three platforms, exactly four possible statuses, exactly five
severity levels), and using an enum makes an invalid value (e.g. a typo'd
severity string) an immediate, loud error instead of a silent bug that only
surfaces later.

### 4.9 Modules, packages, and imports

Any `.py` file is a **module**. A directory containing an `__init__.py`
file (even an empty one) is a **package** — a collection of related
modules that can be imported as a group. Other code brings a module's
contents into scope with `import`:

```python
import os                                    # import the whole module
from pathlib import Path                     # import one specific name
from perdedor_common import FindingFactory      # import from a PERDEDOR package
```

`import os` then requires writing `os.cpu_count()` (dotted access); `from
pathlib import Path` lets you write `Path(...)` directly.

PERDEDOR's Python code is organized into four packages (Volume 2, Chapter 2
gives the exact file layout): `perdedor_common` (shared code: data models,
scoring, validation, reporting — used by every agent), `perdedor_linux`,
`perdedor_android` (the two Python-based platform agents), and `perdedor_cli`
(the command-line entry point that ties everything together). This is the
"modules and packages" idea from Chapter 3.6 in concrete form.

### 4.10 The standard library modules PERDEDOR relies on

- **`os`**: operating-system interaction — reading environment variables
  (`os.environ`), counting CPU cores (`os.cpu_count()`).
- **`pathlib`** (specifically its `Path` class): an object-oriented way to
  work with filesystem paths, e.g. `Path("/proc/meminfo")`,
  `(some_dir / "subfile").exists()`. Preferred throughout this codebase
  over the older, more error-prone string-concatenation approach to
  building paths.
- **`subprocess`**: run *other* programs (external commands) from within
  Python and capture their output — e.g. running `ps -eo comm` to list
  running processes, or invoking the native C helper binary described in
  Chapter 7. `subprocess.run([...], capture_output=True, text=True, timeout=...,
  check=False)` is the exact pattern used throughout PERDEDOR: it runs a
  command, captures its stdout/stderr as text (rather than raw bytes),
  enforces a maximum time limit (so a hung command can't freeze the whole
  scan), and disables automatically raising an exception on a non-zero
  exit code (`check=False`) so the calling code can inspect and handle
  failure itself rather than being forced into exception-handling for
  what's often an entirely expected outcome (e.g. "this tool isn't
  installed on this machine").
- **`socket`**: low-level networking — PERDEDOR uses `socket.gethostname()`
  to read the machine's hostname for its "suspicious hostname" check.
- **`urllib.request`**: make outbound HTTP requests — used for the cloud
  metadata reachability check (Chapter 19 explains what a cloud metadata
  endpoint is and why reaching it matters).
- **`json`**: convert between Python objects and JSON text (Chapter 9
  covers JSON itself in depth) — `json.dumps(obj)` converts a Python
  value to a JSON string; `json.loads(text)` parses JSON text back into
  Python values.
- **`dataclasses`**: covered above (§4.7).
- **`enum`**: covered above (§4.8).
- **`argparse`**: build command-line interfaces — parse the words a user
  types after the program name (like `perdedor test linux --json`) into
  structured data your code can act on. PERDEDOR's CLI (Volume 2, Chapter 8)
  is built entirely on `argparse`.
- **`re`** (regular expressions): pattern-matching against text — e.g.
  validating that a string looks like a MAC address
  (`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$` — Chapter 19 explains what a MAC
  address is; for now, just know a **regular expression** is a compact,
  standardized mini-language for describing "shapes" of text to match
  against, and `re.match(pattern, text)` checks whether `text` matches
  `pattern`).

### 4.11 Exception handling in practice

```python
try:
    urllib.request.urlopen(url, timeout=1.0)
    reachable = True
except Exception:
    reachable = False
```

This is a direct excerpt from PERDEDOR's cloud-metadata check. `try:` marks
the block that might fail; `except Exception:` catches *any* kind of
failure (a deliberately broad catch here, because literally any failure —
timeout, connection refused, DNS failure, etc. — means exactly the same
thing for this specific check: "not reachable," so there's no need to
distinguish between failure reasons). Catching `Exception` this broadly is
usually considered bad practice in general Python code (it can hide real
bugs), which is *why* you'll see a `# noqa: BLE001` comment next to it in
the real source — that's a deliberate instruction to the project's
automated linter (code-quality checker, Chapter 18) saying "yes, I know
this looks too broad, and I mean it anyway, for this specific reason."

### 4.12 Running Python code

- `python3 script.py` runs a single file directly.
- `python3 -m package_name` runs a package as a program (Python looks for
  a special file named `__main__.py` inside that package and runs it) —
  this is exactly how you run PERDEDOR's Linux and Android agents directly:
  `python3 -m perdedor_linux`.
- **pip** is Python's package installer, used to download and install
  third-party packages from the internet (or, as with PERDEDOR itself, to
  install a local project so its modules become importable system-wide):
  `pip install -e .` installs the current project in **editable mode**
  (`-e`), meaning changes to the source files take effect immediately
  without needing to reinstall — extremely useful during development.
- A **virtual environment** (`venv`) is an isolated, self-contained copy
  of the Python installation and its installed packages, kept separate
  from your system-wide Python — so that installing packages for one
  project can never conflict with or break another project's requirements.
  Created with `python3 -m venv .venv` and activated with
  `source .venv/bin/activate` (Linux/macOS) or `.venv\Scripts\activate`
  (Windows) before installing anything.

## Chapter 5: The Command Line and Shell Scripting

### 5.1 What is a shell?

A **shell** is a program that gives you a text-based way to interact with
an OS: you type a command, press Enter, and the shell runs it and shows you
the output. This is called a **command-line interface (CLI)**, in contrast
to a **graphical user interface (GUI)** (windows, icons, menus). Common
shells: **Bash** (the default on most Linux systems and, historically,
macOS), **zsh** (the current macOS default, very similar to Bash),
**PowerShell** (Windows' modern shell, covered fully in Chapter 6). The
visible text-entry window running a shell is often called a **terminal**
or **console**.

PERDEDOR is explicitly, deliberately "CLI-only" — it has no graphical
interface at all. This is a stated design goal, not a limitation: a CLI
tool is trivially scriptable (you can run it automatically as part of a
larger automated process), works identically over a remote connection
where there may be no graphical display at all, and is the natural fit for
a tool aimed at technical analysts who already live in a terminal.

### 5.2 Basic commands

A handful of commands appear throughout PERDEDOR's own checks (as commands the
*agent itself* runs, not just commands you'd type yourself):
- `ps` — list running processes.
- `cat` (or, in PERDEDOR's Python code, simply reading a file directly) —
  show a file's contents.
- `dpkg-query` / `rpm` — list installed packages, on Debian/Ubuntu-family
  and Red-Hat-family Linux systems respectively (Chapter 11 explains why
  Linux has multiple, incompatible package-management systems).
- `fc-list` — list installed fonts on Linux.
- `systemd-detect-virt` — a command, built into `systemd` (Linux's most
  common startup/service-management system, Chapter 11), that
  independently reports what kind of virtualized (or bare-metal)
  environment it thinks it's running in — PERDEDOR uses it as a cross-check
  against its own findings.
- `make` — builds compiled software from source code, following a recipe
  file called a `Makefile` (Chapter 7 covers this fully, since it's how
  PERDEDOR's native C helper gets compiled).

### 5.3 Command syntax: arguments, flags, and pipes

A typical command looks like: `command argument1 argument2 --flag value`.
**Positional arguments** are plain values in a fixed order (like a
function's parameters in Chapter 3.4); **flags** (also called "options" or
"switches") are named, usually optional, and can appear in any order —
conventionally starting with one dash for a single-letter short form
(`-s`) or two dashes for a full-word long form (`--serial`). PERDEDOR's own
CLI follows this exact convention: `perdedor test android -s emulator-5554`
and `perdedor test android --serial emulator-5554` mean the same thing.

The **pipe** operator `|` connects the output of one command directly into
the input of the next, letting you chain small, single-purpose tools
together into a more complex operation without writing any new code — a
foundational Unix philosophy ("do one thing well, then compose"). You'll
see this pattern conceptually mirrored in how PERDEDOR's own `perdedor test`
(produce a report) and `perdedor report` (consume reports, produce a
combined view) commands are designed to be chained together, even though
they're connected via files rather than a literal shell pipe.

### 5.4 Shell scripts

A **shell script** is a text file full of shell commands, run together as
a program — conventionally given a `.sh` extension and started with a
**shebang** line, `#!/bin/bash` or `#!/usr/bin/env bash`, as its very first
line, which tells the OS which interpreter to run the rest of the file
with. PERDEDOR itself doesn't ship shell scripts (its automation is Python
and PowerShell), but understanding shell scripting is essential for
understanding the Linux commands its Python code shells out to via
`subprocess` (§4.10), and for building/testing the project during
development (e.g. the `Makefile` commands covered in Chapter 7 are
typically invoked from a shell).

### 5.5 Exit codes

Every command, when it finishes, produces a numeric **exit code** (also
"return code" or "status code"): `0` conventionally means "success," and
any non-zero value means "some kind of failure" (different tools use
different non-zero values to mean different specific failures). This is a
universal convention across essentially every OS and every command-line
tool ever written, and it's central to how PERDEDOR's native C helper
(Chapter 7) communicates results back to the Python code that invokes it —
Python's `subprocess.run(...).returncode` reads this exact value, and
PERDEDOR's C helper uses *specific* exit codes (0 = success, 1 = usage error,
2 = "not applicable on this hardware") that the Python wrapper code
explicitly checks for and reacts to differently.

### 5.6 Standard streams: stdout, stderr, stdin

Every process has (at least) three built-in communication channels:
- **stdout** ("standard output") — where a program's normal output goes.
- **stderr** ("standard error") — a *separate* channel, conventionally
  used for error messages, warnings, and diagnostic/status text, kept
  deliberately separate from stdout so that a program's real output can be
  captured or piped cleanly without diagnostic noise mixed in.
- **stdin** ("standard input") — where a program reads input from, if it
  needs any (often the keyboard, unless redirected).

This distinction is *load-bearing* in PERDEDOR's own design: its Windows
agent writes status/progress messages to stderr and its actual JSON report
to stdout, specifically so that a caller (like the Python CLI, which
captures the Windows agent's output) can reliably separate "the data" from
"the noise" — mixing these up was a real, documented bug during
development (a `Write-Host` call was polluting stdout with human-readable
text that should have gone to stderr, corrupting the JSON output; Volume 2
covers this fix as a case study).

## Chapter 6: PowerShell and .NET Deep Dive

PERDEDOR's Windows agent is written entirely in PowerShell. This chapter
explains PowerShell from scratch, plus enough of the underlying .NET
runtime to understand why the Windows agent is built the way it is.

### 6.1 What is PowerShell?

PowerShell is Microsoft's modern shell and scripting language, available
on Windows (built in) and, as **PowerShell 7+** ("PowerShell Core"), on
Linux and macOS too (this cross-platform availability is exactly why
PERDEDOR's earlier development sessions were able to test the Windows agent's
logic on a Mac, as covered in Volume 2). Files are conventionally named
`.ps1`. Where Bash is fundamentally text-oriented (commands take and
produce plain text), PowerShell is fundamentally **object-oriented**: every
command produces structured .NET objects with named properties, not just
raw text — you access a piece of data with `$object.PropertyName` rather
than having to parse it back out of formatted text output. This is a
significant design difference from Bash and one of PowerShell's most
distinctive features.

### 6.2 Variables, cmdlets, and pipelines

Variables start with a `$` sigil: `$name = "value"`. PowerShell's built-in
commands are called **cmdlets** (pronounced "command-lets"), conventionally
named `Verb-Noun` (e.g. `Get-Process`, `Get-Service`, `Test-Path`) — this
naming convention is so consistent that you can often guess a cmdlet's
name correctly on the first try. Like Bash, PowerShell supports pipelines
with `|`, but since each stage passes structured *objects* rather than raw
text, you can do things like `Get-Process | Where-Object { $_.CPU -gt 100 }`
(filter processes by an actual numeric property) without any text-parsing
at all. `$_` inside a pipeline block refers to "the current object being
processed."

### 6.3 Functions

```powershell
function Test-Something {
    param([Parameter(Mandatory)][string]$Name)
    return "Hello, $Name"
}
```

`function` defines a reusable named block, directly analogous to Python's
`def`. `param(...)` declares its parameters (PowerShell's equivalent of a
Python function's parameter list); `[Parameter(Mandatory)]` marks a
parameter as required; `[string]` is a type constraint, forcing whatever is
passed in to be treated as a string.

By strong PowerShell convention, functions that test/check something and
return true/false-ish results are named `Test-Something` (mirroring the
built-in `Test-Path` cmdlet) — and PERDEDOR's own check functions follow this
convention exactly: `Test-CpuidHypervisorBit`, `Test-DebuggerPresent`,
`Test-RegistryArtifacts`, and so on are all functions the Windows agent
defines itself, one per check, matching PowerShell's own naming idiom for
"things that test a condition."

**A PowerShell-specific gotcha that mattered during PERDEDOR's development:**
declaring a parameter with an explicit type like `[string]$Value` silently
*converts* `$null` (PowerShell's "no value" / `None` equivalent) into an
empty string `""` the moment it's assigned — because PowerShell tries to
coerce every value into the declared type, and converting "nothing" into
"the empty string" is its default coercion rule for the string type. This
matters enormously for a tool like PERDEDOR that needs to distinguish "no
remediation text because none applies" from "remediation text that happens
to be blank" — Volume 2 covers the exact fix (removing the `[string]` type
constraint on parameters that need to genuinely support `$null`).

### 6.4 The .NET runtime

PowerShell (in its modern, cross-platform form) runs on top of **.NET**
(pronounced "dot net"), Microsoft's software platform and runtime, which
provides an enormous standard library of pre-built functionality — file
I/O, networking, cryptography, and much more — shared between PowerShell,
C#, and other .NET-based languages. When PowerShell code writes something
like `[System.Environment]::ProcessorCount`, it's reaching directly into
.NET's own class library — `System.Environment` is a .NET class, and
`::ProcessorCount` accesses one of its properties (the `::` syntax, rather
than `.`, specifically means "access something that belongs to the class
itself, not to a particular instance of it" — a **static member**).

PERDEDOR's Windows agent leans on .NET intrinsics heavily for reading the CPU
directly (`System.Runtime.Intrinsics.X86.X86Base`, covered fully in
Chapter 10) — this is a deliberate, explicit design choice, called out in
the agent's own README: because this specific .NET feature requires
PowerShell 7+ (not the older "Windows PowerShell 5.1" that ships by
default on older Windows installs), the whole Windows agent has that same
version requirement, and the CLI checks for it explicitly before trying to
run the agent.

### 6.5 P/Invoke — calling native Windows APIs from PowerShell

.NET's standard library covers a huge amount of ground, but not
*everything* the underlying Windows operating system can do — some
capabilities are only exposed through **Win32 API** functions: the
lower-level, decades-old programming interface built directly into
Windows itself, originally designed for C and C++ programs. **P/Invoke**
("Platform Invoke") is the mechanism .NET (and, through it, PowerShell)
provides for calling these native Win32 functions directly from managed
code.

In PowerShell, you set this up with `Add-Type`, giving it a small snippet
of inline C# code that declares the external function's exact signature:

```powershell
Add-Type -Namespace Perdedor -Name Firmware -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern uint GetSystemFirmwareTable(uint FirmwareTableProviderSignature, uint FirmwareTableID, byte[] pFirmwareTableBuffer, uint BufferSize);
'@
```

Breaking this down:
- `Add-Type` compiles the C# text given to it on the fly and makes the
  result available to the rest of the PowerShell script, as if it were a
  built-in .NET type.
- `-Namespace Perdedor -Name Firmware` names the new type `Perdedor.Firmware` —
  afterward, the script calls it as `[Perdedor.Firmware]::GetSystemFirmwareTable(...)`.
- `[DllImport("kernel32.dll", ...)]` is a C# **attribute** (metadata
  attached to a piece of code) that tells .NET "this function isn't
  implemented here — go find it inside `kernel32.dll`" (a **DLL**,
  "Dynamic Link Library," is Windows' equivalent of a shared library: a
  file full of pre-compiled functions that multiple programs can use
  without each needing their own copy — `kernel32.dll` is one of the
  core, always-present Windows system DLLs, exposing many fundamental
  OS-level operations).
- `public static extern uint GetSystemFirmwareTable(...)` declares the
  function's exact name, parameter types, and return type, matching
  Microsoft's own documented signature for this Win32 function *exactly*
  — get this declaration wrong (wrong parameter types, wrong order) and
  the call can crash the whole PowerShell process, since you're now
  directly bridging into raw native memory operations.

PERDEDOR's Windows agent uses this P/Invoke pattern four separate times, each
declared once near the top of the relevant file and reused by every check
that needs it:
- **`Perdedor.Firmware`** (`GetSystemFirmwareTable`, from `kernel32.dll`) —
  reads the *raw* SMBIOS firmware table directly (Chapter 12 explains
  what this table is), bypassing Windows' higher-level WMI/CIM reporting
  layer entirely, to catch spoofing that only fools the higher layer.
- **`Perdedor.Debug`** (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
  `GetCurrentProcess`, from `kernel32.dll`) — classic anti-debugging
  primitives (Chapter 16 explains what a debugger is and why its presence
  matters).
- **`Perdedor.Window`** (`FindWindow`, from `user32.dll`, the core Windows
  GUI-related system DLL) — looks for hidden windows created by specific
  known guest-tool tray applications, by their internal window "class
  name" (an identifier Windows assigns every window, usually invisible to
  the end user, that PERDEDOR can search for even if the actual window itself
  is hidden or minimized).
- **`Perdedor.Mouse`** (`GetCursorPos`, from `user32.dll`) — reads the
  current mouse cursor position, sampled twice a fraction of a second
  apart, as a crude "is a human actually present" signal.

### 6.6 Error handling in PowerShell

PowerShell's `try` / `catch` works much like Python's `try` / `except`
(§4.11):
```powershell
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
}
catch {
    return New-PerdedorFinding -Status error -ErrorDetail "CIM query failed: $($_.Exception.Message)"
}
```
`-ErrorAction Stop` is worth calling out specifically: by default, many
PowerShell cmdlets treat their own errors as "non-terminating" — meaning
they print a warning but keep running, rather than actually triggering a
`catch` block. `-ErrorAction Stop` forces a specific cmdlet call to treat
its own errors as immediately fatal (triggering `catch`), which is exactly
the behavior PERDEDOR's checks need: if a query for hardware information
fails, the check should stop and report an `error` `Finding`, not silently
continue with partial or missing data. `$_` inside a `catch` block refers
to the error/exception object itself; `$_.Exception.Message` reads its
human-readable description.

### 6.7 Registry and WMI/CIM

Windows stores a huge amount of system and application configuration in
the **Windows Registry** — a large, hierarchical (tree-shaped) database
of settings, organized into top-level "hives" like `HKLM` (`HKEY_LOCAL_
MACHINE`, machine-wide settings) and accessed in PowerShell as if it were
a filesystem drive, e.g. `Test-Path -LiteralPath 'HKLM:\SOFTWARE\Oracle\VirtualBox
Guest Additions'` checks whether that specific registry key exists,
exactly the same way you'd check whether a file exists. Guest-integration
software (Chapter 12) very often leaves behind distinctive registry keys,
which is why PERDEDOR's `win.env.registry_artifacts` check tests roughly
thirty known key paths associated with VirtualBox, VMware, Xen, Wine, and
Sandboxie.

**WMI** (Windows Management Instrumentation) and its modern successor
**CIM** (Common Information Model) are Windows' standardized systems for
querying structured information about hardware and OS state — things like
"what is the BIOS manufacturer string," "how much total RAM is installed,"
"what network adapters are present." PowerShell's `Get-CimInstance
-ClassName Win32_ComputerSystem` is exactly this: `Win32_ComputerSystem`
is one of hundreds of predefined WMI/CIM "classes" (each describing one
category of system information), and `Get-CimInstance` queries it,
returning a structured object whose properties you can read directly
(`$cs.Manufacturer`, `$cs.Model`, etc.). PERDEDOR's Windows agent uses several
of these classes: `Win32_ComputerSystem`, `Win32_BIOS`, `Win32_PnPEntity`
(Plug-and-Play devices — hardware components Windows has detected),
`Win32_DiskDrive`, `Win32_NetworkAdapterConfiguration`.

## Chapter 7: C Programming Basics

PERDEDOR's Linux agent includes one small piece of code written in C, rather
than pure Python. This chapter explains why, and teaches enough C to read
that one file.

### 7.1 Why does PERDEDOR need C at all?

Python (Chapter 4) is a high-level language: it deliberately hides most
low-level hardware detail from you, for safety and simplicity. That's
almost always the right tradeoff — but it means Python has **no built-in
way** to execute two very specific, very low-level x86 CPU instructions
that PERDEDOR absolutely needs: `CPUID` (ask the CPU to report information
about itself) and `RDTSC` (read the CPU's internal cycle counter). Neither
of these is a "function you call" in the normal sense — they are literal
CPU instructions, one step below even C, that only a compiled language
talking almost directly to the hardware can issue. Chapter 10 explains
exactly what these two instructions do and why PERDEDOR needs them so much
that it's worth writing (and shipping) a small C program just to reach
them.

C is the natural choice here because it's the lowest-level language that's
still practical to write by hand, it compiles to genuinely native machine
code with no intermediate runtime in the way, and it has direct, standard
support for "inline assembly" — literally embedding raw CPU instructions
inside otherwise-normal C source code.

### 7.2 C syntax basics

C looks structurally similar to Python's control flow but with important
differences: blocks are delimited by curly braces `{}` (not indentation,
though good style still indents consistently), every statement ends with a
semicolon `;`, and — critically — every variable must be declared with an
explicit, fixed type, and that type can never change:

```c
int add(int a, int b) {
    int result = a + b;
    return result;
}
```

`int` here means "32-bit signed integer" specifically (unlike Python's
`int`, which automatically grows to hold numbers of any size, C's numeric
types have a fixed, finite size decided at compile time — this is one of
the main reasons C programs run so much faster than Python: the compiler
knows exactly how much memory and what CPU operations every value needs,
ahead of time, with zero runtime guesswork).

### 7.3 Compilation

Unlike Python, C code cannot run directly — it must first be
**compiled**: translated by a compiler program (common ones: `gcc`, `cc`,
`clang`) from human-readable `.c` source text into a binary **executable**
file full of actual machine instructions for a specific CPU
architecture (Chapter 10 explains what "architecture" means here). This
compiled binary is what actually runs — the original `.c` source text is
no longer needed at run time at all.

A `Makefile` is a small recipe file (named exactly `Makefile`, read by the
`make` command mentioned in Chapter 5.2) that specifies how to build a
project's binary from its source files, including which compiler to use
and which flags/options to pass it, so that "build this project" is always
just the one command `make`, regardless of how complex the actual
compilation steps are. PERDEDOR's native helper has exactly this: a `Makefile`
alongside its C source, and the Python wrapper code that needs the
compiled binary runs `make` automatically, the very first time it's
needed, if the binary doesn't already exist — so a user never has to
manually compile anything themselves.

### 7.4 Pointers and memory (the core C concept)

The single most distinctive feature of C, and the source of most of its
learning difficulty, is that it gives you **direct, manual control over
memory** — with none of the safety nets Python provides automatically.

Every piece of data in a running program lives somewhere in memory, at a
numeric **address**. A **pointer** is a variable whose value *is* a memory
address — i.e., instead of holding a piece of data directly, it holds
"where to find" that data. This is an extremely powerful but
extremely dangerous tool: get a pointer wrong (point it at memory you
don't actually own, or use it after the memory it pointed to has been
freed) and the program can crash, corrupt unrelated data, or — in the
worst case, when exploited maliciously — be hijacked into running
attacker-controlled code. (This exact class of bug — memory-safety bugs in
C/C++ code — is one of the most historically significant sources of
real-world security vulnerabilities, and is a large part of *why*
languages like Python, Rust, and Go, which manage memory automatically and
safely, have become so popular for new software.)

PERDEDOR's own C helper is small and carefully scoped specifically to
minimize this risk — it does a handful of narrow, well-understood
operations (read CPU registers, read a timer, print the results as text)
and nothing more, precisely because "small and simple" is one of the best
defenses against memory-safety bugs in C.

### 7.5 Structs

A C `struct` ("structure") groups related pieces of data under one name —
directly analogous to a simple Python class or dataclass with no methods:

```c
struct CpuidResult {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
};
```

`unsigned int` means "a 32-bit integer that can only be zero or positive"
(no negative numbers) — an appropriate type for CPU register contents,
which are really just raw bit patterns being interpreted as numbers, not
meaningfully "signed" quantities at all. PERDEDOR's C helper uses a struct
exactly like this one to hold the four register values (`EAX`, `EBX`,
`ECX`, `EDX`) that the `CPUID` instruction produces (Chapter 10 explains
what these four registers mean).

### 7.6 Inline assembly

**Assembly language** is the lowest-level, human-readable representation
of actual CPU instructions — one assembly instruction typically
corresponds to exactly one real CPU operation, with none of C's
higher-level conveniences (no variables in the everyday sense, no control-
flow keywords — just direct manipulation of registers and memory). C
allows embedding raw assembly instructions directly inside otherwise
normal C code, called **inline assembly**, using a compiler-specific
extension (GCC and Clang both support the syntax `asm volatile (...)`).
This is precisely how PERDEDOR's native helper issues the `CPUID` and
`RDTSC` instructions — there is no other way to reach them from C (or any
other language) except through exactly this mechanism, because they are
not "library functions" at all; they are literal CPU opcodes with no
higher-level API wrapping them.

### 7.7 Standard input/output in C

C's standard library provides `printf` (formatted print — "print
formatted") for writing text to stdout (Chapter 5.6), and functions like
`atoi`/`strtol` for parsing text into numbers. PERDEDOR's C helper's entire
"interface" to the outside world is exactly this: it's a tiny
command-line program that takes a couple of text arguments (which CPUID
leaf to query, or how many timing iterations to run), and prints its
result as one line of simple `key=value key=value` text to stdout — this
plain-text format is intentionally the simplest possible interface for the
calling Python code (§4.10's `subprocess` pattern) to parse back apart with
basic string splitting, with no need for a more complex data format.

### 7.8 Architecture guards and portability

C code that includes inline assembly for one specific CPU family (x86)
will not even *compile* on a different CPU family (like ARM, common on
Apple Silicon Macs and most Android devices) — the assembly instructions
simply don't exist there. PERDEDOR's C source handles this with a
**preprocessor conditional**: `#if defined(__x86_64__) || defined(__i386__)`
... `#else` ... `#endif`. The C preprocessor is a text-substitution step
that runs *before* actual compilation, and `__x86_64__`/`__i386__` are
predefined macros (symbols) that the compiler automatically sets based on
which CPU architecture it's currently targeting. This lets the same source
file compile successfully on any machine: on x86 hardware it compiles in
the real CPUID/RDTSC logic, and on anything else it compiles in a small
stub that immediately reports "not applicable" (via a specific exit code,
§5.5) instead of failing to build at all. This is exactly the kind of
graceful-degradation design principle that runs throughout the entire
PERDEDOR project (Chapter 18 covers it as a named theme), applied here at the
lowest possible level — inside a single C file.

## Chapter 8: Git and Version Control

### 8.1 What problem version control solves

As soon as more than one person (or even just one person, over time) works
on a piece of software, you need a way to answer questions like: "what
changed since yesterday?", "who changed this line, and why?", "can I
safely undo this change without losing everything else?", "can two people
work on different parts of the same project at the same time without
overwriting each other?" A **version control system (VCS)** answers all of
these by tracking the complete history of every change ever made to a
project's files.

**Git** is, by a wide margin, the most widely used version control system
today. It's a **distributed** VCS, meaning every person's local copy of a
project (called a **repository**, or "repo") contains the *entire* project
history, not just the current files — there's no single central server
required for it to function (though in practice, most teams do use a
shared central copy, commonly hosted on a service like GitHub, as the
agreed-upon "source of truth").

### 8.2 The core concepts

- **Repository ("repo")**: a project directory, plus its entire tracked
  history, managed by Git. Created with `git init`, or obtained by
  **cloning** (copying) an existing one with `git clone <url>`.
- **Commit**: a saved snapshot of the entire project at one point in time,
  along with a short human-written message describing what changed and
  why. Every commit (except the very first) points back to the commit that
  came immediately before it, forming a chain — the project's full
  history. Creating one is a two-step process: `git add <files>` (or
  `git add -A` for everything) marks which changes you want to include
  ("staging" them), then `git commit -m "message"` actually creates the
  snapshot.
- **Branch**: an independent, parallel line of commits, letting you work
  on something (a new feature, an experiment) without touching the
  project's main line of history until you're ready. The default main
  branch is conventionally named `main` (or, in older projects, `master`).
- **Diff**: a comparison between two versions of a file (or the whole
  project), showing exactly which lines were added, removed, or changed —
  the fundamental unit of "what happened" in version control. `git diff`
  shows this.
- **Merge**: combining changes from one branch back into another.
- **Remote**: a copy of the repository hosted elsewhere (typically on a
  server like GitHub) that your local repository can exchange commits
  with. `git push` sends your local commits to a remote; `git pull` (or
  `git fetch` + `git merge`) brings a remote's commits into your local
  copy.
- **`.gitignore`**: a file listing patterns for files/directories Git
  should never track (e.g. compiled binaries, temporary files, files
  containing secrets). PERDEDOR's own `.gitignore` excludes things like the
  compiled native-helper binary (§7.3) and generated JSON report files —
  because these are *outputs*, reproducible from the tracked source at
  any time, not source material that needs its own history.

### 8.3 Why this matters for a project like PERDEDOR

Beyond simple backup/collaboration, Git's history is itself a form of
documentation: `git log` shows the sequence of commits (and their
messages) that built up the project over time, and `git blame <file>`
shows, line by line, which commit last touched each line and why. This
project's own internal conventions (covered fully in Chapter 18) require
every commit message to explain *why* a change was made, not just *what*
changed — because the diff already shows *what* changed; only a human
can explain *why*.

## Chapter 9: JSON and Schemas

### 9.1 What is JSON?

**JSON** (JavaScript Object Notation, pronounced "jay-son") is a simple,
human-readable text format for representing structured data — numbers,
strings, booleans, `null`, lists (called **arrays** in JSON), and
key-value objects — that has become the de facto universal standard for
exchanging data between programs, regardless of what language each program
is written in. Despite the name, it has nothing to do with JavaScript
specifically anymore — literally every mainstream programming language,
including Python and PowerShell, can read and write it.

A small JSON example:
```json
{
  "platform": "linux",
  "hostname": "my-machine",
  "findings": [
    {"id": "linux.env.cpuid_hypervisor_bit", "status": "clean", "severity": "critical"},
    {"id": "linux.env.dmi_sys_vendor", "status": "detected", "severity": "high"}
  ]
}
```
Curly braces `{}` delimit an **object** (key-value pairs, keys always
quoted strings); square brackets `[]` delimit an **array** (an ordered
list); values can be strings (in double quotes), numbers, `true`/`false`,
`null`, or nested objects/arrays.

This is *exactly* the format every PERDEDOR agent produces as its report, and
exactly the format `perdedor report` reads back in to combine multiple
reports together — JSON is the literal, physical "glue" connecting every
piece of this project, precisely because it's the one format every part
of the project (Python code, PowerShell code, a human reading it directly
in a text editor) can all read and write natively, with zero translation
needed.

### 9.2 Converting to/from JSON in code

- **Python**: the built-in `json` module (§4.10). `json.dumps(some_dict)`
  converts a Python dictionary (or list, string, number, etc.) into a JSON
  text string; `json.loads(some_text)` parses JSON text back into Python
  values (a JSON object becomes a Python dict, a JSON array becomes a
  Python list, and so on — the mapping between JSON's types and Python's
  types is direct and predictable).
- **PowerShell**: `ConvertTo-Json` and `ConvertFrom-Json` cmdlets do the
  same job.

Neither Python's `Finding`/`PlatformReport` dataclasses (§4.7) nor
PowerShell's equivalent hashtables are *themselves* JSON — they're native
in-memory data structures in each language. PERDEDOR's `to_dict()` method
(covered fully in Volume 2) is the explicit conversion step: turning a
Python object into a plain dictionary/list/string structure that
`json.dumps` can then serialize. This conversion step is necessary because
JSON has no concept of "a `Finding` object" — it only knows about its five
basic building blocks (object, array, string, number, boolean/null), so
any custom data type must be explicitly translated down into those
building blocks before it can be written out as JSON, and translated back
up after being read back in.

### 9.3 What is a schema?

A **JSON Schema** is itself written in JSON, and describes the *shape*
another piece of JSON is required to have — which fields must be present,
what type each field must be, which values are allowed, and so on. It's
the JSON world's equivalent of a rulebook or contract: "any report that
claims to be a valid PERDEDOR report MUST have a `platform` field that is one
of exactly `windows`/`linux`/`android`, MUST have a `findings` array where
every element has an `id`, a `status` that's one of `clean`/`detected`/
`error`/`skipped`, ..." and so on.

Why does this matter for PERDEDOR specifically? Because PERDEDOR has **three
independent agents, written in two completely different programming
languages** (Python and PowerShell), that all need to produce output in
*exactly* the same shape, so that a downstream tool (like `perdedor report`,
which combines reports from all three platforms into one unified view) can
treat them identically without needing separate code paths per platform.
The schema (`schema/perdedor-report.schema.json` in the actual repo) is the
single, authoritative, language-independent definition of that shared
shape — the Python agents and the PowerShell agent were each built
independently to match it, and PERDEDOR includes its own **validator**
(covered in Volume 2, `perdedor_common/validation.py`) that checks any given
report against this schema and raises a clear, specific error naming
exactly which rule was violated, if any report — from any agent — ever
drifts out of the exact agreed-upon shape.

## Chapter 10: Computer Architecture Deep Dive

This chapter goes back to the CPU (Chapter 1.5) and goes *much* deeper —
deep enough to fully understand the single most technically intricate part
of PERDEDOR: its direct use of the `CPUID` and `RDTSC` CPU instructions.

### 10.1 Instruction sets and architectures

An **instruction set architecture (ISA)**, often just "architecture," is
the specific vocabulary of raw instructions a particular family of CPUs
understands — which operations exist, what they're called (in assembly,
Chapter 7.6), and exactly how they behave. Compiled programs (Chapter
3.1/7.3) are translated into instructions from one specific ISA, which
means a program compiled for one architecture generally cannot run
directly on a CPU of a different architecture at all.

The two architectures relevant to PERDEDOR:
- **x86 / x86-64** (also called **AMD64** or **x64**): the architecture
  used by essentially all traditional desktop/laptop/server PCs (both Intel
  and AMD chips implement it) — this is where "x86" originally referred to
  a numbering scheme for a lineage of Intel chips (8086, 80286, 80386...)
  and the name stuck, even now that it's a 64-bit architecture. "x86-64" or
  "x64" specifically means the modern 64-bit version; plain "x86" (or
  "i386") sometimes specifically means the older 32-bit version, so "x86"
  is used both as a family name and as a specific-variant name — context
  usually makes clear which is meant.
- **ARM**: a completely different architecture, dominant in
  battery-powered/mobile devices — every Android phone's CPU is ARM, and
  Apple's own "Apple Silicon" Macs (M1/M2/M3/M4 chips) are ARM too.

**Why this matters enormously for PERDEDOR**: `CPUID` and `RDTSC` (below) are
x86-*specific* instructions — they do not exist at all on ARM. This single
fact is the direct reason PERDEDOR's native C helper has the architecture
guard described in Chapter 7.8, and the direct reason several of PERDEDOR's
checks explicitly report `skipped` (not `error`, not `clean` — a
deliberately distinct third outcome) when run on non-x86 hardware: the
check genuinely does not apply there, which is a fundamentally different
situation from "the check applies but failed."

### 10.2 Registers, revisited

Chapter 1.5 introduced registers as the CPU's small number of extremely
fast internal storage slots. On x86, the "general-purpose" registers most
relevant here are named `EAX`, `EBX`, `ECX`, `EDX` (the `E` prefix
historically stood for "extended," from when these were widened from an
even older 16-bit generation of registers named `AX`, `BX`, `CX`, `DX`; on
the modern 64-bit architecture there's a further-widened set prefixed `R`
instead — `RAX`, etc. — but PERDEDOR works at the 32-bit `E`-register level
throughout, which is sufficient for everything it needs). Each of these
four registers holds exactly 4 bytes (32 bits) — no more, no less. They
have no fixed meaning by themselves; any given instruction defines what it
expects to find in them, and what it will leave in them afterward. This is
exactly why the `CPUID` instruction (next section) is described entirely
in terms of "what goes into `EAX` before the call, and what comes back in
`EAX`/`EBX`/`ECX`/`EDX` after it."

### 10.3 The `CPUID` instruction

`CPUID` is a single x86 CPU instruction whose entire purpose is
self-description: "tell me about yourself." You put a specific number
(called a **leaf**, sometimes "function number") into the `EAX` register,
execute the `CPUID` instruction, and the CPU overwrites `EAX`, `EBX`,
`ECX`, and `EDX` with information corresponding to that leaf. Different
leaf numbers ask for completely different categories of information —
there are dozens of standardized leaves, covering things like the CPU
manufacturer's name, which optional CPU features are supported (does this
CPU support a specific kind of fast math instructions, etc.), cache sizes,
and — critically for PERDEDOR — whether a hypervisor is present at all, and
if so, which one.

Three specific leaves matter to PERDEDOR, and it's worth understanding each
precisely, because getting even one detail wrong here produces a
*silently* wrong answer rather than a crash (this happened for real during
PERDEDOR's development — see Volume 2's bug case study):

- **Leaf `0`** ("get vendor ID"): returns, packed across `EBX`, `EDX`, and
  `ECX` — in that specific order — a 12-character ASCII string identifying
  the actual physical CPU manufacturer, e.g. `"GenuineIntel"` or
  `"AuthenticAMD"`. PERDEDOR doesn't directly use leaf 0 itself, but
  understanding its register order (`EBX`, `EDX`, `ECX`) matters because it
  is the order most public documentation and tutorials describe first —
  and it is *not* the same order used by the hypervisor leaf below, which
  is the exact trap that caused a real bug in this project.
- **Leaf `1`** ("feature information"): among many other things, bit 31
  of the `ECX` register returned by this leaf is the **hypervisor-present
  bit**. Every mainstream hypervisor (Chapter 12) deliberately sets this
  bit to `1` when a guest OS asks — it's the official, documented, sanctioned
  way for a hypervisor to tell a guest "yes, you are virtualized," so that
  well-behaved guest software can enable virtualization-aware
  optimizations. Ironically, this same, entirely legitimate signal is one
  of the very first things a sandbox-evasive piece of malware checks too —
  it's a single bit, trivially fast to check, and reliably present. PERDEDOR's
  `check_cpuid_hypervisor_bit` (Linux) / `Test-CpuidHypervisorBit`
  (Windows) checks literally read this exact bit.
- **Leaf `0x40000000`** ("hypervisor vendor ID," only meaningful when the
  bit above is set): a *different* hypervisor-specific 12-character ASCII
  string identifying *which* hypervisor is present (e.g. `"KVMKVMKVM\0\0\0"`
  for KVM, `"VMwareVMware"` for VMware, `"Microsoft Hv"` for Hyper-V) —
  and this string is packed across `EBX`, `ECX`, and `EDX`, in *that*
  order — deliberately, confusingly, **different** from leaf 0's `EBX`,
  `EDX`, `ECX` order. This isn't a mistake in the standard; it's simply an
  independent convention set by the hypervisor vendors (loosely following
  Xen's original precedent) that happens not to match leaf 0's older,
  separately-defined convention. PERDEDOR's own code comments call this out
  explicitly as "an easy, silent-wrong-answer bug" — because swapping
  `ECX` and `EDX` here doesn't crash anything; it just silently decodes
  into garbage text that will never match any known hypervisor's
  signature, making a real KVM/QEMU guest incorrectly report "clean"
  on this specific check. Volume 2 shows exactly where this bug was
  caught and fixed, and the regression test written specifically to make
  sure it never comes back unnoticed.
- **Leaves `0x80000002` through `0x80000004`** ("processor brand
  string"): three consecutive leaves whose combined output, taken
  straight across `EAX`, `EBX`, `ECX`, `EDX` (in that plain, non-tricky
  order, for each of the three leaves in sequence), spells out a
  human-readable CPU model name string, up to 48 characters — the exact
  same string you'd see in, say, Windows' System Information panel. Real
  physical CPUs report their actual marketing name here (e.g. "Intel(R)
  Core(TM) i7-9700K CPU @ 3.60GHz"). Hypervisors, however, very often
  report an obviously synthetic name instead — QEMU's default is
  literally `"QEMU Virtual CPU version 2.5+"`; this is, historically, one
  of the very first checks the original Pafish tool ever implemented
  (Chapter 17), because it's such an easy, blunt, and reliable tell.

### 10.4 The `RDTSC` instruction and timing-based detection

`RDTSC` ("ReaD Time-Stamp Counter") is a second x86 instruction, entirely
unrelated in mechanism to `CPUID` but closely related in *purpose*: it
reads a 64-bit counter, built directly into the CPU hardware, that
increments (essentially) once per CPU clock cycle since the machine last
started. Reading it twice, with some work done in between, tells you
*exactly* how many CPU cycles that work took — a much finer-grained,
lower-overhead measurement than any OS-provided timer could give you.

Why does this matter for detecting virtualization? Because certain
operations — and `CPUID` is the textbook example — cannot be handled
directly by a virtual CPU at all; they must be intercepted by the
hypervisor itself, a process called a **VM exit** (Chapter 12 explains
this fully). A VM exit is drastically more expensive, in raw CPU cycles,
than an ordinary instruction: control has to leave the guest entirely, get
handled by the hypervisor's own code running on the *real* CPU, and then
return back into the guest. On real, non-virtualized hardware, `CPUID`
executes in perhaps a few dozen cycles; under most hypervisors, a
`CPUID`-triggered VM exit can take many hundreds to low thousands of
cycles — a difference easily large enough to detect just by timing it with
`RDTSC` immediately before and after.

This is exactly PERDEDOR's `linux.timing.rdtsc_cpuid_jitter` check: it
executes `RDTSC`, then `CPUID`, then `RDTSC` again, thousands of times in
a tight loop, and looks at how the resulting cycle counts are distributed
(their minimum, median, mean, maximum, and how spread-out/"jittery" they
are). Real hardware tends to produce fast, *stable* numbers, run after
run; virtualized environments tend to produce slower, *more erratic*
numbers, because of the added VM-exit overhead and the general noisiness
of sharing real hardware with a hypervisor and possibly other guests.
Chapter 15 covers this as one of the four major evasion-technique
categories in its own right.

**Why is this only implemented with real precision on the Linux agent
using the native C helper (Chapter 7), and only approximated on Windows?**
Because — as covered in §6.4 — .NET simply does not expose an `RDTSC`
intrinsic the way it exposes `CPUID` (via `X86Base`). Windows' `RDTSC`
substitute check instead uses .NET's `Stopwatch` class (built on a
Windows facility called **QPC**, "QueryPerformanceCounter" — a
high-resolution, but still OS-mediated, and therefore inherently *coarser*
timer than a direct hardware register read). PERDEDOR's own code and
documentation are explicit and honest about this being a heuristic
approximation, not a true cycle-accurate measurement, rather than silently
overstating its own precision — an example of the "documented boundaries"
principle covered in Chapter 18.

### 10.5 Byte order (endianness) — the piece that makes register decoding actually work

When a 4-byte register value like `EBX` is *reinterpreted* as 4 individual
ASCII text characters (as happens when decoding a vendor-ID string out of
CPUID's output), the order those 4 bytes get laid out in matters, and this
is governed by a CPU-architecture-wide property called **endianness**. x86
CPUs are **little-endian**, meaning the *least*-significant byte of a
multi-byte value is stored first (at the lowest memory address / read out
first), rather than the most-significant byte first (**big-endian**,
used by some other architectures, and also, confusingly, by the way
humans normally write numbers left-to-right).

In code, this is exactly why you'll see `.to_bytes(4, "little")` in
PERDEDOR's Python (§4.4) — explicitly telling Python "take this 32-bit
number and lay its bytes out little-endian-style" — and why the
PowerShell equivalent uses `[BitConverter]::GetBytes(...)`, relying on
.NET's `BitConverter` to do the equivalent conversion for the machine
it's actually running on (x86, in this case, so also little-endian).
Getting endianness backwards is a second, completely independent way to
silently corrupt a decoded string, distinct from the register-*order*
mistake in §10.3 — both have to be correct, together, for the decoded
vendor string to come out as readable text at all instead of scrambled
garbage.

### 10.6 Cores, threads, and hyper-threading

Chapter 1.5 introduced CPU cores as independent execution units on one
chip. Many modern CPUs additionally support **simultaneous
multithreading (SMT)** (Intel calls its specific implementation
**Hyper-Threading**) — presenting each physical core to software as *two*
logical processors, sharing some of that core's internal resources, to
squeeze out extra performance when one logical thread is stalled waiting
on something. From software's point of view (and from `os.cpu_count()` /
`[System.Environment]::ProcessorCount`, which is exactly what PERDEDOR's
"low core count" checks read), you generally cannot tell the difference
between "N real physical cores" and "N/2 physical cores with SMT" purely
from a plain count — both simply report "N logical CPUs." This is a minor
but honest caveat worth knowing: PERDEDOR's core-count check is a coarse
heuristic, not a precise measurement of physical silicon.

## Chapter 11: Operating System Internals

Chapter 2 covered universal OS concepts. This chapter goes deep into the
specific internals of the three operating systems PERDEDOR targets.

### 11.1 Linux: everything is (sort of) a file

A defining Linux/Unix philosophy is that the kernel exposes an enormous
amount of live system information as ordinary-looking files, readable
with completely ordinary file-reading code — no special API, no special
permissions (for most of them), just "open this path and read the text
inside." PERDEDOR's Linux agent leans on this philosophy almost entirely;
notice how few of its checks need to run an external command at all,
compared to how many just read a file directly.

**`/proc`** ("the proc filesystem," procfs) is a **virtual filesystem** —
it doesn't correspond to real data sitting on a disk anywhere; instead,
the kernel generates its contents live, on demand, the instant something
reads them. It exposes live information about running processes (each
process gets a directory `/proc/<pid>/`) and overall system state:
- `/proc/uptime` — how long the system has been running (in seconds),
  read by PERDEDOR's low-uptime check (Chapter 15 explains why low uptime
  matters at all).
- `/proc/meminfo` — detailed memory statistics, including `MemTotal:`,
  read by PERDEDOR's low-RAM check.
- `/proc/modules` — every kernel module (see §11.2) currently loaded,
  read by PERDEDOR's guest-kernel-module check.
- `/proc/scsi/scsi` — information about SCSI-protocol storage devices
  (a decades-old but still widely used storage protocol/standard),
  including vendor strings, read by PERDEDOR's SCSI-vendor check.
- `/proc/1/cgroup` — control-group membership (§13.2) of process ID 1
  (the very first process the kernel starts, and therefore the ultimate
  ancestor of every other process) — read by PERDEDOR's container-detection
  check, since a distinctive `cgroup` path here is one of the strongest
  signals that the process is running inside a container rather than
  directly on a full OS install.
- `/proc/version` — kernel version and build information as free text;
  Microsoft's WSL ("Windows Subsystem for Linux," a compatibility layer
  that runs a real Linux kernel/userland *inside* Windows) leaves the word
  "microsoft" right in this string, which PERDEDOR checks for directly.

**`/sys`** (sysfs) is a second, separate virtual filesystem, more
structured and more specifically organized around hardware devices and
kernel objects (as opposed to `/proc`'s slightly more historical,
grab-bag organization):
- `/sys/class/dmi/id/*` — the SMBIOS/DMI firmware information described
  in §1.7, exposed as one small file per field (`sys_vendor`,
  `product_name`, `bios_vendor`, `board_vendor`, etc.) — PERDEDOR's Linux
  agent reads eleven of these fields, each independently, because
  different hypervisors are inconsistent about which specific fields they
  bother to spoof, so checking only one or two would miss real evidence
  sitting in the others.
- `/sys/bus/pci/devices/*/vendor` — one file per PCI device (§1.6),
  giving that device's raw vendor ID in hex — read by PERDEDOR's virtio/PCI
  vendor-ID check.
- `/sys/block/*/device/{vendor,model}` and `/sys/block/*/size` — per-disk
  vendor/model strings and raw size (in 512-byte sectors — PERDEDOR's code
  multiplies by 512 to convert to bytes), read by PERDEDOR's block-device
  and small-disk checks.
- `/sys/class/net/*/address` — each network interface's MAC address
  (Chapter 19 explains MAC addresses), read by PERDEDOR's MAC-OUI check.

### 11.2 Linux kernel modules

The Linux kernel supports loading additional code into itself *after*
boot, without recompiling or restarting — a **kernel module** (a `.ko`
file). This is how most hardware drivers work: rather than the kernel
having every possible driver for every possible piece of hardware built in
permanently (which would be enormous and mostly wasted), only the modules
actually needed for the hardware present get loaded. `/proc/modules`
(above) lists every module currently loaded. PERDEDOR's guest-kernel-module
check specifically looks for module name prefixes belonging to
paravirtualized guest drivers — `virtio` (generic), `vboxguest`/`vboxsf`/
`vboxvideo` (VirtualBox), `vmwgfx`/`vmw_balloon`/`vmw_vmci` (VMware),
`xen_`/`hv_`/`hyperv_` (Xen/Hyper-V) — because loading one of these
modules at all is only possible/meaningful inside the corresponding
hypervisor's guest.

### 11.3 systemd

**systemd** is the startup and service-management system used by most
mainstream Linux distributions today — it's the very first real userspace
process the kernel starts (PID 1, referenced in §11.1 above), and it's
responsible for starting every other service, mounting filesystems, and
generally bringing the system the rest of the way up after the kernel
itself has finished initializing. Among its many built-in utilities,
`systemd-detect-virt` is a small command specifically designed to answer
"what kind of virtualized (or non-virtualized/'bare metal') environment am
I running in?" — using systemd's own independent detection logic (which
overlaps with, but is maintained completely separately from, PERDEDOR's own
checks). PERDEDOR runs this command and treats its answer as an independent
cross-check against everything else it found — if PERDEDOR's own CPUID/DMI
checks come back "clean" but `systemd-detect-virt` reports `"kvm"` anyway,
that's a strong signal something in PERDEDOR's own spoofing coverage has a
gap.

### 11.4 Linux package managers

Different Linux distributions ("distros" — distinct, independently
packaged and maintained Linux-based operating systems, e.g. Ubuntu,
Debian, Fedora, Arch) use different **package managers** — tools for
installing, removing, and tracking installed software — and, critically,
these are *not* interchangeable or compatible with each other. The two
families relevant to PERDEDOR: Debian/Ubuntu-based systems use `dpkg`
(and its friendlier front-end `apt`), queryable with `dpkg-query`;
Red Hat/Fedora-based systems use `rpm` (and its friendlier front-end
`dnf`/`yum`), queryable with `rpm -qa`. PERDEDOR's installed-package-count
check (part of its "behavioral / wear-and-tear" category, Chapter 15) has
to try both, because it has no way of knowing in advance which family a
given Linux install belongs to, and gracefully accepts that neither may
be present at all (e.g. inside a minimal container) by reporting
`skipped` rather than crashing.

### 11.5 Windows internals, continued

Chapter 6.7 already covered the Windows Registry and WMI/CIM. A few more
Windows-specific concepts used by PERDEDOR:

- **Services**: introduced in §2.7 — background processes managed
  centrally by Windows, queryable with `Get-Service`. PERDEDOR's guest-
  service check looks for services named things like `VBoxService`,
  `VMTools`, `vmware-tools`, `qemu-ga`.
- **PnP (Plug and Play) devices**: Windows' system for automatically
  detecting and configuring attached hardware, queryable via the
  `Win32_PnPEntity` WMI/CIM class (§6.7) — each entry has a `DeviceID`
  string that embeds the same PCI vendor-ID concept from §1.6, in text
  form (e.g. containing `VEN_1AF4` for a virtio device).
- **Environment variables** like `%LOCALAPPDATA%` (a per-user folder for
  application-specific data, used by PERDEDOR's browser-history check to
  find where Chrome/Edge store their history file) and `%USERPROFILE%`
  (the current user's home folder, used by PERDEDOR's aged-files check).

### 11.6 Android internals

Android is built on top of the Linux kernel, but its userspace (the layer
above the kernel — Chapter 2.2) is almost entirely different from a
traditional Linux desktop distribution — no systemd, no `/etc/passwd`
in the traditional sense for regular apps, a completely different
application model (apps run inside a managed runtime, heavily sandboxed
from each other by default, using Linux's own user-ID-based isolation
creatively). A few Android-specific concepts PERDEDOR's Android agent relies
on directly:

- **`getprop` / system properties**: Android maintains a large,
  flat key-value store of system configuration, called **system
  properties** — things like the device's build identifier, hardware
  name, and countless other settings — readable with the `getprop`
  command (optionally with one specific property name, or with none, to
  dump everything). This is functionally similar to a very simplified
  version of the Windows Registry (§6.7), specific to Android. PERDEDOR's
  Android agent reads dozens of these properties, because Android's own
  emulator implementations (covered next, and in Chapter 12) set very
  distinctive values for many of them by default.
- **The Android Emulator, Goldfish, and Ranchu**: Google's own official
  Android emulator (part of the Android SDK, used constantly by app
  developers to test apps without needing a physical phone) is itself a
  QEMU-based virtual machine (Chapter 12 explains QEMU), historically
  using a customized Android-specific virtual hardware platform codenamed
  **Goldfish**, and more recently a newer one codenamed **Ranchu**. Both
  leave extremely distinctive fingerprints — property values that
  literally contain the word `"goldfish"` or `"ranchu"`, virtual device
  files with those names, and so on — which is exactly what several of
  PERDEDOR's Android checks search for directly.
- **`ro.kernel.qemu`**: one single, extremely blunt system property that
  the goldfish/ranchu emulator kernel sets to `1`, existing for no reason
  other than "yes, this is the emulator" — real devices never set it at
  all (not "set it to 0" — it's simply absent). This is exactly the
  distinction covered in §4.5/§2 about `None`/absence-of-data mattering:
  PERDEDOR's check for this property has to specifically distinguish "the
  device is unreachable, so I don't know" from "the device is reachable,
  and this property is genuinely just not set" (which is the *normal,
  expected, real-device* case) from "the device is reachable, and this
  property is explicitly set to 1" (a definite detection) — three
  different situations that a naive implementation could easily conflate
  into just two, which is exactly the real bug documented as a case study
  in Volume 2.
- **libhoudini**: many Android emulator configurations run on an x86 (or
  x86-64) virtual CPU for performance reasons (x86 emulation is generally
  much faster on the x86-based development machines most engineers use,
  compared to fully emulating a real ARM CPU in software), but most
  real-world Android apps ship native code compiled specifically for ARM.
  To bridge this gap, some emulator images include **libhoudini** — a
  proprietary binary-translation layer (conceptually similar in *purpose*
  to Apple's Rosetta 2, which lets Intel-compiled Mac apps run on Apple
  Silicon, or Windows' own x86-on-ARM emulation) that translates ARM
  machine code into x86 machine code on the fly, letting ARM-only apps run
  anyway. Its mere presence on a device is a strong signal that the
  device's *real* underlying CPU is x86, which is itself unusual/
  suspicious for anything claiming to be a real Android phone (real
  phones are essentially universally ARM). PERDEDOR checks for this both
  directly (file-presence checks for the actual `libhoudini`-related
  files) and indirectly (checking whether the reported CPU ABI —
  Application Binary Interface, essentially "which instruction set/
  calling-convention family this software was compiled for" — claims to
  be x86 at all).
- **`adb` (Android Debug Bridge)**: the standard command-line tool for
  communicating with an Android device or emulator from a separate
  computer, over USB or over a network connection — used for installing
  apps, viewing logs, and, relevant here, running arbitrary shell commands
  on the device (`adb shell <command>`) and reading its system properties
  (`adb shell getprop <name>`, or the shorthand `adb shell getprop`
  wrapped by many tools, PERDEDOR included, as `adb.getprop`). Every single
  Android check PERDEDOR runs goes through `adb` — this is a deliberate
  architectural choice (covered in the Android agent's own README, and
  explained further in Chapter 12/Volume 2) to avoid needing to build and
  install a dedicated companion app on the device at all: `adb` alone is
  already enough to reach the great majority of what PERDEDOR needs to
  check.
- **`dumpsys`**: an Android system command that dumps detailed diagnostic
  information about a specific system service — e.g. `dumpsys battery`
  reports current battery charge level, charging state, and temperature;
  `dumpsys sensorservice` lists every hardware sensor (accelerometer,
  gyroscope, proximity sensor, etc.) the device claims to have. PERDEDOR's
  Android agent parses this command's free-text output directly (using
  the regular-expression pattern-matching from §4.10) since, unlike
  `getprop`, `dumpsys` has no simpler structured-output mode for these
  particular subsystems.
- **`pm` (Package Manager)**: the on-device command for querying and
  managing installed apps — `pm list packages -3` lists only third-party
  ("-3" = not part of the base OS image) installed apps, used by PERDEDOR's
  installed-app-count check (a mobile-specific version of the same
  "wear and tear" idea from §11.4's desktop package-count check); `pm
  list features` lists hardware/software capabilities the device claims
  to support (e.g. `android.hardware.camera`), used by PERDEDOR's
  camera-feature check.

## Chapter 12: Virtualization Deep Dive

Virtualization is the technology at the very center of this entire
project — PERDEDOR exists to detect it. This chapter explains what it
actually is, mechanically, from the ground up.

### 12.1 What is virtualization?

**Virtualization** is the technique of running one or more complete,
independent "computers" — each with its own OS, its own virtual CPU,
virtual memory, virtual disks, virtual network card — as software,
*inside* a real, physical computer. Each such simulated computer is called
a **virtual machine (VM)**, or a **guest**; the real physical computer
underneath is called the **host**; and the software layer that creates
and manages the VMs is called a **hypervisor** (also "Virtual Machine
Monitor," VMM).

Why do this at all? Enormous practical value: you can run many isolated
operating systems on one physical server (huge cost savings, the
foundation of essentially all modern cloud computing); you can test
software against many different OS configurations without needing
separate physical machines for each; and — the reason this matters
directly to PERDEDOR/CHIMERA — you can safely run and observe **untrusted or
malicious software** inside a disposable, isolated guest, without
risking the real host machine, and can discard/reset the guest instantly
afterward.

### 12.2 Type 1 vs. Type 2 hypervisors

- A **Type 1 hypervisor** ("bare-metal") runs directly on the physical
  hardware, with no general-purpose host OS underneath it at all — the
  hypervisor itself *is* the lowest software layer. Examples: VMware ESXi,
  Xen, Microsoft Hyper-V (in its full server deployment mode). These are
  the norm in large-scale data centers and cloud providers, because
  running without a full general-purpose OS underneath reduces overhead
  and attack surface.
- A **Type 2 hypervisor** ("hosted") runs as an ordinary application on
  top of a regular, general-purpose host OS (Windows, Linux, macOS) —
  Oracle VirtualBox and VMware Workstation/Fusion are the classic
  examples. These are the norm for individual developers/analysts running
  a VM or two on their own desktop.

**KVM** (Kernel-based Virtual Machine), which comes up constantly in this
project (and in CHIMERA, the sandbox platform PERDEDOR was built to support),
is interesting because it blurs this line: it's a feature *built directly
into the Linux kernel itself*, turning an ordinary Linux installation into
a Type-1-like hypervisor without needing separate bare-metal hypervisor
software — Linux itself becomes the hypervisor for any VMs it hosts, while
still being usable as a normal general-purpose OS at the same time.

### 12.3 Hardware-assisted virtualization

Early virtualization (1990s-2000s) had to work around a hard problem:
naively running a guest OS's privileged instructions directly on the real
CPU is unsafe (a guest could interfere with the host or other guests), but
*trapping and emulating* every privileged instruction in pure software is
extremely slow. Modern CPUs solve this with dedicated hardware support —
Intel's **VT-x** and AMD's **AMD-V** (both introduced in the mid-2000s) —
extra CPU modes and instructions specifically designed to let a hypervisor
run guest code *almost* directly on the real CPU, safely, with the CPU
itself automatically intercepting only the specific operations that
genuinely need the hypervisor's involvement (this hardware-assisted
interception-and-handoff is precisely the mechanism behind the **VM exit**
concept introduced in §10.4). KVM is built specifically to use this
hardware support (it will not function on a CPU without VT-x/AMD-V, or if
that feature is disabled in the system firmware settings), and this
hardware-level foundation is exactly why the timing-based detection in
§10.4/Chapter 15 works at all: a VM exit isn't a software convention that
a clever hypervisor could simply choose to skip — it's a real, physical
transfer of control the underlying hardware itself performs.

### 12.4 QEMU

**QEMU** ("Quick EMUlator") is a hugely important, versatile piece of open-
source software that can operate in two very different modes:

1. **Full emulation mode**: QEMU can simulate an *entire, different*
   computer purely in software — including simulating a CPU of a
   completely different architecture than the host's real CPU (e.g.
   simulating an ARM CPU while running on an x86 host). This is
   dramatically slower than hardware-assisted virtualization (because
   *every single instruction* has to be translated/interpreted in
   software) but it's the only option when guest and host architectures
   genuinely differ — this is exactly the mode CHIMERA's Android track
   uses, deliberately, to run genuine ARM Android guests on x86 analysis
   hosts, specifically to avoid needing something like libhoudini
   (§11.6) at all.
2. **Hardware-accelerated mode (paired with KVM)**: when guest and host
   share the same real architecture, QEMU can hand off the actual CPU
   execution to KVM (§12.3) and hardware virtualization, using its own
   software only to emulate the surrounding virtual hardware (disk
   controllers, network cards, graphics, etc.) — this "QEMU/KVM" pairing
   is the standard, high-performance way to run x86 Linux VMs, and is the
   specific hypervisor combination CHIMERA's own KVM hardening work (the
   report that originally motivated PERDEDOR's creation) is built around.

### 12.5 Paravirtualization and VirtIO

Fully emulating a piece of real hardware (a real disk controller, a real
network card) in software, faithfully enough that an unmodified guest OS's
existing real-hardware driver can talk to it, works, but is unnecessarily
slow — the guest driver still behaves as if it's talking to genuinely slow
real hardware (issuing individual small commands and waiting), even though
the "hardware" underneath is actually just another program running on the
same physical machine, capable of vastly faster communication if only the
guest knew to expect it.

**Paravirtualization** solves this by having the guest OS load
*special* drivers that are specifically aware they're talking to a
hypervisor, using an interface *designed* for fast software-to-software
communication rather than mimicking old physical hardware protocols.
**VirtIO** is the modern, standardized paravirtualization interface used
by QEMU/KVM (and other hypervisors) — a family of virtual devices
("virtio-net" for networking, "virtio-blk"/"virtio-scsi" for storage,
etc.) that only exist as a concept inside virtualized environments, with
no physical hardware equivalent at all.

This directly explains one of PERDEDOR's richest and most reliable detection
signals: because VirtIO devices are registered on the guest's PCI bus
(§1.6) with a specific, publicly documented vendor ID (`0x1af4`,
officially assigned to Red Hat for exactly this purpose), simply
enumerating PCI devices and checking their vendor IDs (PERDEDOR's
`pci_virtio_devices`/`pnp_virtual_devices` checks) reliably identifies a
QEMU/KVM guest — because *no real physical device ever legitimately uses
that vendor ID*; its only possible meaning is "this is a virtio device,"
which itself only exists inside a virtual machine.

### 12.6 Guest additions / guest tools

Beyond the low-level VirtIO-style paravirtualized *hardware* drivers,
most hypervisors also ship an optional, higher-level companion software
package meant to be installed *inside* the guest OS, to improve the
day-to-day experience of using a VM — things like a shared clipboard
between host and guest, automatic screen-resolution adjustment, shared
folders, and time synchronization. VirtualBox calls this "Guest
Additions"; VMware calls it "VMware Tools"; QEMU/KVM's equivalent is
called the "QEMU Guest Agent" (`qemu-ga`). These almost always install as
a background service/daemon (§2.7), leave distinctive files on disk, and
often register distinctive registry keys (on Windows, §6.7). Because
they're aimed at making a VM *nicer to use interactively* rather than at
being stealthy, they tend to be extremely easy, unambiguous detection
signals — PERDEDOR checks for their processes/services, their files on disk,
and (on Windows) their registry footprint, as three independent, largely
redundant checks, precisely because catching *any one* of these is
already close to definitive proof.

### 12.7 SMBIOS/DMI spoofing, and why PERDEDOR reads it twice (Windows)

Returning to §1.7's introduction of SMBIOS/DMI: because this firmware-
level identity data is such a rich, blunt detection signal, hardening a VM
against detection very often includes deliberately overriding these
strings to look like plausible real hardware (e.g. libvirt, a popular
management layer on top of QEMU/KVM, supports a `<sysinfo>` XML block for
exactly this purpose). But there's a subtlety worth understanding: on
Windows, the *ordinary*, easy way to read this information is through WMI/
CIM (`Win32_ComputerSystem`, `Win32_BIOS` — §6.7), which is a fairly high-
level Windows subsystem, itself just another *consumer* of the same
underlying firmware table. It is technically possible for a spoofing setup
to intercept and rewrite what WMI reports *without* actually correcting
the true, lower-level raw table underneath — which would fool a naive
checker that only looks at WMI, while leaving the real evidence sitting
completely untouched, one layer down. This is exactly why PERDEDOR's Windows
agent *also* reads the raw SMBIOS table directly via the
`GetSystemFirmwareTable` Win32 API (§6.5) and scans its raw bytes for the
same vendor signatures, entirely independently of what WMI reports — two
genuinely different data sources, checked separately, specifically to
catch spoofing that only covers one of them.

### 12.8 Cloud virtualization and instance metadata

Modern cloud computing (AWS, Google Cloud, Azure, and others) is itself
built on large-scale virtualization — when you "rent a server" from a
cloud provider, you're really being given a VM, running on a hypervisor
managed by that provider, on hardware you'll never see or touch directly.
Cloud VMs additionally expose a special, standardized, link-local (Chapter
19 explains this term) HTTP endpoint — conventionally at the IP address
`169.254.169.254` — called the **instance metadata service (IMDS)**,
which the VM itself can query to learn things like its own cloud-assigned
ID, region, and configuration. This address is only ever reachable from
*inside* a cloud VM (or certain container platforms that deliberately
proxy it) — an ordinary laptop or a non-cloud-hosted VM will simply get no
response at all when trying to reach it. PERDEDOR's cloud-metadata-
reachability check exploits exactly this: it doesn't need to understand or
parse *any* of the metadata content — the mere fact that *something*
answered at all, within a short timeout, is already conclusive proof this
machine is a cloud VM. This is a genuinely novel check (as PERDEDOR's own
code comments note) that none of the older prior-art tools (Chapter 17)
include, because they mostly predate mainstream cloud-based malware
detonation infrastructure.

## Chapter 13: Containers Deep Dive

### 13.1 Containers vs. virtual machines

A **container** is a different, lighter-weight form of isolation than a
full virtual machine (Chapter 12). Where a VM simulates entire separate
hardware and runs its own complete, independent OS kernel, a container
shares the *same* underlying host OS kernel as everything else on the
machine, but uses kernel features to make a group of processes *believe*
they have their own private filesystem, their own private process list,
their own private network stack, and so on — an illusion of isolation,
built entirely out of careful kernel-level bookkeeping, without the
overhead of actually running a second full OS.

This makes containers dramatically faster to start (often under a second,
versus tens of seconds or more for a VM) and much lighter on memory/disk
(no duplicate kernel, no duplicate OS installation) — but with a real,
fundamental tradeoff: because the kernel itself is genuinely shared, a
container's isolation is inherently weaker than a real VM's (a serious
enough kernel-level bug can potentially let a process "escape" a container
in ways that are structurally impossible with a real VM, where the guest
never had direct access to the host kernel at all).

**Docker** is by far the most widely used container platform/toolset,
providing a simple command-line interface and file format (a
**Dockerfile**, describing how to build a reusable, shareable filesystem
snapshot called a **container image**) on top of Linux's lower-level
container primitives, below.

### 13.2 The Linux kernel features containers are built from

- **Namespaces**: a Linux kernel facility that gives a group of processes
  their own private, isolated *view* of some global kernel resource — a
  PID namespace makes a process see itself as PID 1 (or some other small
  number) even though it's really some large PID from the host's true,
  global process list; a network namespace gives a group of processes
  their own private network interfaces and routing table, separate from
  the host's; a mount namespace gives them their own private view of the
  filesystem tree. A container is, mechanically, mostly "a group of
  processes placed into a fresh set of namespaces."
- **cgroups** ("control groups"): a separate Linux kernel facility for
  *limiting and accounting* resource usage (CPU time, memory, disk I/O) for
  a group of processes — used by container platforms to enforce "this
  container may use at most 512MB of RAM," and so on.

### 13.3 Why containers are trivially detectable — and why that's a *different problem* than VM detection

Because a container shares its host's real kernel, several of the
richest VM-detection signals covered in Chapter 12 (CPUID hypervisor
bit, SMBIOS/DMI vendor strings, PCI device enumeration) are often
*completely absent or unaffected* inside a container — a container
running on bare-metal Linux, with no VM underneath it at all, will show a
perfectly ordinary, un-virtualized CPUID and DMI, because from the
kernel's point of view, nothing about the underlying hardware has changed.
Container detection instead relies on an entirely different set of
signals, specific to the namespace/cgroup mechanism itself:
- The literal marker file `/.dockerenv`, which the Docker runtime creates
  inside every container it starts, purely as a simple, deliberate "yes,
  you're in a Docker container" flag with no other purpose.
- The container's own `/proc/1/cgroup` (§11.1) contents, which typically
  contain readable strings like `docker`, `lxc` (a different, older
  container runtime), or `kubepods` (Kubernetes, a container-orchestration
  platform) baked right into the cgroup path itself.

PERDEDOR's `linux.env.container_or_wsl` check looks for exactly these two
signals (plus, separately, the WSL kernel-version-string check from
§11.1) — bundled into one check because, conceptually, they're all
answering the same underlying analyst question: "is this detonation
environment actually the strongly-isolated real VM CHIMERA's threat model
assumes, or is it actually a much more weakly-isolated container (or WSL
compatibility layer) instead?" — a distinction that matters enormously for
genuine malware analysis safety, independent of whether any *malware-
facing* evasion signal is present at all.

### 13.4 Why PERDEDOR's own development used Docker

A separate, important point: Docker containers are also simply a
convenient, fast, disposable, real-Linux testing environment for
*developing and validating* PERDEDOR's Linux agent itself — running
`docker run --rm python:3.12-slim ...` gives you a genuine, fresh Linux
environment (with, notably, its own genuinely different DMI/PCI/cgroup
reality than your actual host machine) in seconds, without needing an
actual VM at all. This project's own Linux README documents exactly this
practice, and it's a good general lesson: **the tool used to test/develop
something is not always the same category of thing the tool is checking
for** — PERDEDOR uses containers as a development convenience while its
actual detection logic is aimed at virtual machines, and it also happens
to have a check that tells the two apart when it matters.

## Chapter 14: Malware Analysis and Sandboxes

### 14.1 What is malware?

**Malware** ("malicious software") is any software deliberately designed
to cause harm, gain unauthorized access, steal information, or otherwise
act against the interests of the system or person running it — viruses,
worms, trojans, ransomware, spyware, and many other categories all fall
under this umbrella term. **Malware analysis** is the discipline of
studying a piece of malware — usually a sample obtained from an infected
system, a suspicious email attachment, or a threat-intelligence feed — to
understand what it does, how it spreads, what it's after, and how to
detect and stop it.

### 14.2 Static vs. dynamic analysis

There are two broad, complementary approaches to analyzing a piece of
software you suspect is malicious:

- **Static analysis**: examining the file *without running it* — looking
  at its raw bytes, its structure, embedded text strings, and (with
  reverse engineering tools, Chapter 16) its actual disassembled
  instructions, all while it stays safely inert on disk.
- **Dynamic analysis**: actually *running* the suspected malware, in a
  controlled, observed, disposable environment, and watching what it
  actually does in practice — what files it creates, what network
  connections it makes, what registry keys it touches, and so on. This is
  often far more revealing than static analysis alone (some malicious
  behavior is genuinely hard to predict just by reading code, especially
  code deliberately obfuscated to resist static analysis) — but it's also
  inherently risky, because you are, by definition, letting real malicious
  code actually execute.

### 14.3 What is a sandbox, and what does "detonation" mean?

In this context, a **sandbox** is a deliberately isolated, disposable
execution environment — almost always a virtual machine (Chapter 12),
sometimes a container (Chapter 13) — built specifically to safely perform
dynamic analysis: you run ("**detonate**," in the field's own common
terminology — the malware "goes off" like a controlled explosive, safely,
inside a contained space) the suspect sample inside it, an automated
system observes and records everything that happens, and then the entire
sandbox is discarded (or reset to a known-clean starting **snapshot**) —
so that whatever damage the malware actually did is completely and
permanently contained, with zero lasting effect on any real system.

Modern automated malware-analysis pipelines run this detonation process at
huge scale — often processing thousands of suspicious files per day,
fully automatically, producing a structured report of observed behavior
for each one, which security teams and automated detection systems then
use to build defenses.

### 14.4 CHIMERA: the project PERDEDOR was built to support

This entire PERDEDOR project exists as a companion tool to **CHIMERA**, a
hardened, multi-platform malware-detonation sandbox built around exactly
this idea, using KVM (§12.2) as its underlying hypervisor. CHIMERA's own
design work involved extensively studying and closing exactly the kind of
detection gaps this document has been describing throughout — its own
internal report explicitly verified its hardening against three specific,
well-known open-source detection tools (Pafish, al-khaser, and VMAware —
covered fully in Chapter 17) as a way of measuring "how convincingly does
this sandbox pass as a real machine?"

During that work, CHIMERA's own documentation identified a specific,
concrete gap: those three verification tools only cover Windows and Linux
— none of them support Android at all, and none of them share a common
report format that would let you score a mixed fleet of Windows, Linux,
*and* Android sandboxes consistently, side by side. **PERDEDOR is the tool
built to close exactly that gap** — a single, unified, cross-platform
self-test suite, aiming for parity with (and, on Android, coverage well
beyond) those three tools' combined technique catalog, sharing one report
format and one scoring method across all three platforms.

### 14.5 Why malware bothers to detect sandboxes at all

From a malware author's point of view, being detonated inside an
analyst's sandbox is close to the worst possible outcome: it means their
sample's exact behavior gets fully recorded, studied, and turned directly
into detection signatures and defenses — usually within hours. Because of
this, a very large fraction of real-world malware includes deliberate,
active checks (collectively "anti-sandbox" or "anti-analysis" logic) that
try to determine, *before* doing anything genuinely malicious, whether
it's currently running inside an analysis sandbox — and if so, to behave
completely differently (do nothing at all, or do something harmless and
misleading) specifically to produce a boring, useless analysis report and
starve the defenders of real information. This is the exact behavior
category PERDEDOR exists to test a sandbox *against*, from the defender's own
side: by running the same categories of checks a real piece of
sandbox-evasive malware would run, an analyst can find and fix a sandbox's
weaknesses *before* real malware ever gets the chance to exploit them.

### 14.6 The "golden image" concept

A **golden image** is a carefully prepared, hardened, "as realistic as
possible" template VM disk image — set up once, with deliberate attention
to removing/spoofing every detectable artifact a project like CHIMERA
knows about, and then frozen and reused (or freshly cloned) for every
future detonation, rather than reconfiguring a fresh VM from scratch each
time. PERDEDOR's checks are specifically meant to be run *against a golden
image, before it's ever used for a real detonation* — nearly every one of
PERDEDOR's "remediation" suggestions (the fix text attached to a `detected`
finding) is phrased in exactly these terms: "fix this on the golden image
before freezing it," not "fix this live, during an active detonation,"
because live analysis environments deliberately have zero tooling running
inside them at all (the exact opposite of PERDEDOR's own approach — see
§14.7 below).

### 14.7 Why PERDEDOR runs *inside* the guest, unlike CHIMERA's real detonation model

This is a subtlety worth being explicit about, because it could otherwise
look like a contradiction: CHIMERA's actual malware-detonation sandboxes
are deliberately **agentless** — meaning no extra software runs inside the
guest at all during a real detonation, specifically *because* the presence
of any unusual extra software/process is itself exactly the kind of thing
sophisticated malware checks for (this is the "design-specific" detection
category from Chapter 15). PERDEDOR, by contrast, absolutely does run
directly inside the target (whichever platform it's testing). There is no
real contradiction here, because PERDEDOR is never used during an actual
detonation — it's an *analyst-run self-test*, executed deliberately,
by a human, against a golden image, specifically *before* that image is
ever used to detonate anything real. Pafish and al-khaser (Chapter 17)
work exactly the same way — they are themselves ordinary executables, run
manually inside a candidate VM specifically to test it, never run
alongside real malware during a genuine analysis session.

## Chapter 15: Malware Evasion Techniques — The Four-Category Model

Every single check PERDEDOR runs is tagged with exactly one of four
**detection categories**, a classification scheme that comes directly
from CHIMERA's own theoretical model of sandbox-evasion techniques
(originally laid out in CHIMERA's design chapter 3.2). Understanding these
four categories deeply is the single most important conceptual piece of
this entire document, because it's the organizing principle behind
*every* file in PERDEDOR's codebase (Volume 2 will show you exactly where
each category shows up in the actual source).

### 15.1 Category 1: `environment_artifact`

**Definition**: static, at-rest evidence, sitting in the environment
itself, that identifies it as virtualized/emulated — independent of any
running behavior or elapsed time. This is "look at what's *lying around*"
detection.

This is the largest and generally most reliable category, because
virtualization software has to invent an enormous amount of fake
hardware/firmware identity for a guest to see (Chapter 12 covered exactly
why), and it's very easy for some piece of that fake identity to leak an
obvious tell. Concrete examples, all of which PERDEDOR checks for on at least
one platform:
- CPU vendor/hypervisor-presence signatures via `CPUID` (§10.3).
- SMBIOS/DMI firmware strings (§1.7, §12.7) — motherboard/BIOS/chassis
  vendor names.
- PCI device vendor IDs identifying paravirtualized hardware (§12.5).
- Loaded guest-integration kernel modules/services/registry keys/files on
  disk (§12.6).
- Suspiciously round or minimal hardware specs (very few CPU cores, very
  little RAM, a very small disk) — real everyday machines tend to have
  specs above certain practical thresholds; disposable sandbox VMs are
  often provisioned minimally, purely to save cost, without much thought
  given to how "normal" the numbers look.
- Container/WSL markers (§13.3) and cloud-metadata-endpoint reachability
  (§12.8).
- Android-specific: build-fingerprint strings, `ro.kernel.qemu`, goldfish/
  ranchu device nodes, libhoudini presence (§11.6).

### 15.2 Category 2: `timing`

**Definition**: detection based on measuring *how long things take*,
exploiting the fact that virtualization (and, even more so, full software
emulation) reliably introduces measurable performance overhead compared to
running directly on real hardware.

Concrete examples:
- The RDTSC-around-CPUID VM-exit-timing technique from §10.4 — measuring
  the actual cost, in raw CPU cycles, of an operation that's cheap on real
  hardware but expensive under virtualization.
- Low system uptime — a sandbox VM that gets freshly booted specifically
  for each detonation will have a suspiciously short uptime compared to a
  real user's everyday machine, which typically stays running (or at
  least stays logged-in/unlocked) for extended periods. This is a much
  cruder technique than cycle-level RDTSC timing (it operates on the scale
  of minutes, not CPU cycles) but it's simple, reliable, and was one of
  the very earliest sandbox-evasion techniques ever documented (the
  original Pafish tool, Chapter 17, calls this exact check `GetTickCount`
  timing, after the underlying Windows API it originally used).

### 15.3 Category 3: `behavioural_interaction`

**Definition**: detection based on the *absence of evidence a real human
has actually been using this machine* over time — sometimes called "wear
and tear" detection, after the specific academic research (Miramirkhani
et al.'s work on this exact topic, cited directly in PERDEDOR's own code
comments) that popularized the idea. A disposable sandbox VM, freshly
provisioned for each detonation and then discarded, will never accumulate
the small, mundane signs of genuine, ongoing human use that a real
person's everyday machine naturally builds up over months or years.

Concrete examples:
- Shell/browser history — a near-empty history file is implausible for a
  machine claiming ongoing real use.
- Filesystem "age" — very few files older than some threshold (e.g. a
  week) suggests everything on this machine was created recently,
  specifically for this session.
- Installed software/package/app count — a machine with almost nothing
  installed beyond the bare OS defaults looks freshly provisioned rather
  than genuinely lived-in.
- Installed font count — real desktop systems accumulate/ship with dozens
  to hundreds of fonts; a minimal/headless provisioning often has far
  fewer.
- Running process count — a genuinely active desktop session has many
  more background processes running than a machine sitting at a bare,
  freshly-booted state.
- Mouse cursor movement (Windows) — sampling the cursor position twice, a
  short delay apart, and checking whether it moved at all, as a very
  crude "is a human actually present and interacting with this machine
  right now" signal.
- Android: third-party installed app count, battery charge-state and
  temperature plausibility (a battery that's *permanently* at a suspicious
  fixed value, like exactly 50% and always AC-powered, is itself
  implausible — real batteries drain and recharge, and their temperature
  drifts with use).

### 15.4 Category 4: `design_specific`

**Definition**: quirks of *this particular analysis platform's own
design/setup*, as opposed to virtualization-in-general. This category is
explicitly framed, in CHIMERA's own theoretical model, as the category a
tool like PERDEDOR has to keep *continuously current on* — because, unlike
the other three categories (which are rooted in relatively stable,
long-lived technical facts about how CPUs and hypervisors work), this
category is really about "did whoever set up this specific analysis
environment leave behind some specific, avoidable, human mistake" — a
moving target that depends entirely on the particular choices made when
building a particular sandbox, and can drift out of date the moment
someone changes a hostname convention or leaves a debugging tool running.

Concrete examples:
- Analysis/debugging tooling actively running in the process list
  (Wireshark, gdb, IDA, Ghidra, and dozens of others — Chapter 16 explains
  what several of these tools actually are) — their mere presence is a
  strong, direct signal that "a human analyst is currently watching this
  machine," entirely independent of any virtualization-specific evidence
  at all.
- Implausible hostnames/usernames — machines literally named things like
  `"sandbox"`, `"malware-analysis-01"`, or `"test"` are an easy, avoidable,
  but surprisingly common real-world mistake.
- Suspicious/known virtual-NIC MAC address prefixes ("OUI," Chapter 19) —
  many hypervisors default to a specific, publicly documented range of MAC
  addresses for their virtual network adapters, unless the operator
  deliberately overrides it.
- Windows-specific: blacklisted DLLs loaded into the current process
  (indicating hook/sandbox-agent injection), hidden guest-tool tray-
  application window classes, and classic anti-debugging API results
  (`IsDebuggerPresent` and friends — Chapter 16 explains what a debugger
  actually is).
- Android-specific: implausible telephony/baseband identity strings, an
  unrealistically small sensor count, missing camera hardware declaration,
  `"test-keys"` build signing (a marker that a build is a development/
  engineering build rather than a shipped consumer release), and the
  Android emulator's well-known default NAT network subnet
  (`10.0.2.0/24`) still being in use unchanged.

### 15.5 Why this four-category split matters for scoring, not just organization

Beyond being a useful mental model, this categorization is *load-bearing*
in PERDEDOR's actual output: every `Finding` in a report is tagged with
exactly one of these four categories, and PERDEDOR's human-readable and
aggregated reports group findings by category, so an analyst reviewing
results can immediately see *where* a sandbox's weaknesses cluster — e.g.
"this sandbox has excellent environment-artifact hardening but terrible
behavioral wear-and-tear" is a genuinely different, actionable diagnosis
than "this sandbox is uniformly weak across the board," and the category
tagging is what makes that distinction visible at a glance rather than
requiring an analyst to mentally sort dozens of individual findings
themselves.

## Chapter 16: Reverse Engineering and Debugging Basics

### 16.1 What is reverse engineering?

**Reverse engineering** is the process of figuring out how something
works by examining the finished thing itself, without access to its
original design documents or source code. In software, this specifically
means taking a compiled program (Chapter 3.1/7.3 explained that compiling
throws away the original human-readable source text, leaving only raw
machine instructions) and working *backwards* from those raw instructions
toward an understanding of what the program actually does — essential for
malware analysis, since malware authors obviously don't hand out their
source code.

### 16.2 Disassemblers and decompilers

- A **disassembler** converts raw machine code back into assembly
  language (§7.6) — a faithful, one-to-one, human-readable listing of
  every actual instruction, in the order the CPU will execute them. This
  is always possible (machine code unambiguously corresponds to specific
  instructions) but assembly is tedious and low-level to read in bulk.
- A **decompiler** goes a step further, attempting to reconstruct
  something resembling the *original higher-level source code* (readable
  more like C) from the disassembled instructions — an inherently
  imperfect, "best guess" process, since a lot of the original source's
  structure (variable names, comments, sometimes even the original control
  flow) is genuinely lost during compilation and can only be approximately
  reconstructed, not perfectly recovered.

Well-known tools in this space: **IDA Pro** (a long-standing, powerful
commercial disassembler/decompiler, an industry standard for professional
reverse engineering), **Ghidra** (a free, open-source alternative
originally developed by the NSA and released publicly in 2019), and
**radare2**/**r2** (a free, open-source, more command-line-oriented
alternative). All three appear directly in PERDEDOR's own list of "known
analysis tool process names" (§15.4) — their mere presence running on a
machine is itself one of PERDEDOR's design-specific detection checks.

### 16.3 Debuggers

A **debugger** is a tool that lets you run a program *under close,
interactive supervision* — pausing its execution at chosen points
(**breakpoints**), stepping through it one instruction (or one line of
source, if available) at a time, and inspecting/modifying the exact
contents of its memory and CPU registers as it runs. Debuggers are
essential for both legitimate software development (finding bugs) and
dynamic malware analysis (watching exactly what a sample does, one step at
a time, rather than just observing its end effects). Well-known debuggers:
**x64dbg** (free, Windows-focused), **gdb** (GNU Debugger, free,
Linux-focused, also usable on other platforms), **WinDbg** (Microsoft's
own official Windows debugger), **Evan's Debugger** ("edb," Linux GUI
debugger).

### 16.4 Anti-debugging techniques

Because a debugger gives an analyst enormous, fine-grained visibility into
exactly what a program does, malware very commonly includes deliberate
**anti-debugging** checks — logic that tries to detect whether it's
currently running under a debugger, and if so, behaves differently (exits
immediately, or does something deliberately misleading) specifically to
frustrate step-by-step analysis. PERDEDOR implements a representative,
*intentionally limited* subset of the many known anti-debug techniques,
on Windows specifically, using two genuinely simple, well-documented Win32
API functions covered in §6.5:

- **`IsDebuggerPresent`**: the single most basic anti-debug primitive —
  it simply checks a specific flag Windows itself maintains, per-process,
  recording whether a debugger is currently attached.
- **`CheckRemoteDebuggerPresent`**: a closely related but distinct check,
  specifically catching debuggers attached *out-of-process* (from a
  separate analysis tool watching the target process from outside, a
  common technique for evading the simpler `IsDebuggerPresent` check
  alone).
- PERDEDOR additionally checks .NET's own managed-code equivalent,
  `System.Diagnostics.Debugger.IsAttached`, specific to whether a *managed*
  (.NET) debugger is attached to the PowerShell process itself.

### 16.5 What PERDEDOR deliberately does *not* implement, and why

This is a good, concrete example of the "documented boundaries" principle
covered fully in Chapter 18: real-world malware anti-debug logic goes
*vastly* further than the three checks above — inspecting hardware
debug registers directly, reading a specific flag (`BeingDebugged`) inside
a low-level Windows data structure called the **PEB** (Process Environment
Block, an internal per-process bookkeeping structure Windows maintains,
not part of any officially documented/stable public API), deliberately
setting the CPU's **trap flag** to detect single-instruction-stepping,
and dozens more similarly deep techniques. PERDEDOR's own documentation is
explicit and honest that these deeper techniques are out of scope for a
PowerShell-based agent — genuinely reaching them would require either
unsafe, low-level native code well beyond a simple P/Invoke declaration
(§6.5), or reaching directly into undocumented internal Windows structures
that aren't part of any stable, supported API at all. This is a real,
acknowledged gap, not an oversight — and it's called out explicitly, in
writing, in the project's own coverage documentation, rather than silently
left unmentioned (a deliberate policy this project follows throughout, and
one worth learning as a general lesson in honest technical documentation:
**explicitly stating what a tool does *not* do is just as valuable as
documenting what it does**).

## Chapter 17: The Prior Art — Pafish, al-khaser, and VMAware

PERDEDOR was explicitly built to reach parity with (and, on Android, go
beyond) three specific, well-established open-source tools. Understanding
what each one actually is — and isn't — is essential context for
understanding PERDEDOR's own design.

### 17.1 Pafish ("Paranoid Fish")

**Pafish** is a small, focused, open-source Windows/Linux executable whose
entire purpose is to run a curated set of the most well-known,
"classic" sandbox/VM-detection techniques and report which ones would
have fired — effectively letting a sandbox operator experience exactly
what a moderately sophisticated piece of malware would see, without
needing actual malware at all. It's historically significant as one of
the earliest, most widely referenced tools of exactly this kind, and its
name is a small joke: paranoid *fish* — as in "even a fish would be
paranoid enough to check its surroundings before committing to anything."
Pafish's technique catalog tends to focus on a relatively small number of
high-signal, "classic" checks — CPUID vendor/brand strings, a handful of
registry keys, and simple timing checks like `GetTickCount`-based uptime.

### 17.2 al-khaser

**al-khaser** ("the loser," a mildly self-deprecating Arabic-derived
name chosen by its author) is a much larger, more exhaustive open-source
Windows tool covering a far broader technique catalog than Pafish —
dozens of registry keys across multiple hypervisors, an extensive
analysis-tool process blacklist, DLL-injection and anti-dumping
self-tests, a substantial anti-debugging section (§16.4), and a "Human
Interface" section (mouse movement, font/process counts) that directly
inspired PERDEDOR's own behavioral checks of the same names. Because of its
sheer breadth, al-khaser is generally treated as the more thorough,
harder-to-fully-pass reference implementation of "what would a genuinely
determined piece of malware check for," and it's the single largest
individual source of technique inspiration for PERDEDOR's own Windows and
Linux check catalogs (PERDEDOR's own coverage documentation cites it, by
name, dozens of times).

### 17.3 VMAware

**VMAware** is a more modern, actively maintained, cross-platform C++
*library* (rather than a single standalone executable like the two tools
above) — meaning it's meant to be embedded directly into other software
as a reusable detection component, exposing both individual technique
checks and an aggregated overall score. Its scoring approach (`clean/
total` as a headline number, alongside a more nuanced weighted
assessment) directly inspired PERDEDOR's own two-number scoring design
(§18.4 and Volume 2 cover this exactly). VMAware is also notable for
including some of the more technically involved checks PERDEDOR borrows
from directly, like raw SMBIOS firmware-table scanning (§12.7) rather
than relying solely on higher-level OS-provided hardware-info APIs.

### 17.4 What none of the three do — the gap PERDEDOR fills

Despite their real strengths, all three tools share the same fundamental
limitation that motivated PERDEDOR's creation: **none of them support
Android**, and **none of them share a common output format** with each
other — each produces its own bespoke text/console output, with no way
to programmatically combine results from, say, a Windows run and a Linux
run into one consistent, comparable report, let alone add Android
results into that same picture. An organization (like the one behind
CHIMERA) that needs to verify hardening across a genuinely mixed fleet of
Windows, Linux, *and* Android sandboxes has no way to do that with a
single, consistent tool and workflow using Pafish/al-khaser/VMAware alone
— they'd need three (or, for Android, effectively zero, since nothing
comparable exists at all) completely separate tools, each with its own
output format, requiring manual, error-prone reconciliation to get any
kind of unified picture. This is precisely the gap PERDEDOR is built to
close — one CLI, one report schema (Chapter 9), one scoring method,
across all three platforms.

## Chapter 18: Security Engineering Practices Used in This Project

This chapter steps back from PERDEDOR's specific technical subject matter and
covers the general software-engineering *practices* the project follows —
practices that apply to building reliable, trustworthy software of any
kind, not just security tools.

### 18.1 Automated testing and Test-Driven Development

A **test** is a small piece of code whose entire job is to check that some
*other* piece of code behaves correctly — running it with known inputs
and automatically verifying it produces the expected output, rather than
a human having to manually check by hand, every single time, forever. A
collection of tests is a **test suite**, typically run with a dedicated
**test framework** — PERDEDOR's Python code uses **pytest**, the most widely
used Python testing framework, which automatically discovers and runs
every function in the `tests/` directory whose name starts with `test_`,
and reports which passed and which failed.

- A **unit test** checks one small, isolated piece of logic in complete
  isolation (e.g. "does the severity-weighted scoring formula produce the
  right number for this specific input?").
- An **integration test** checks that multiple pieces work correctly
  *together* (e.g. PERDEDOR's `test_windows_agent_report.py` actually runs
  the real PowerShell agent script and verifies its real output validates
  against the real JSON schema — testing the whole pipeline end-to-end,
  not just one function in isolation).
- A **regression test** is a test written specifically *after* fixing a
  real bug, whose entire purpose is making sure that exact bug can never
  silently come back unnoticed in the future. PERDEDOR's codebase has
  several of these, each with a comment explaining the original bug in
  detail — e.g. the CPUID register-order test from §10.3, and the
  Android "device unreachable vs. property genuinely unset" test from
  §11.6. Reading these tests' comments is, in a real sense, reading a
  small, documented history of every mistake this project's own
  developers actually made and caught.
- **Mocking**: a technique for testing code that depends on something
  external/unpredictable (a network connection, a real device, the actual
  current time) by temporarily substituting a fake, controlled stand-in
  for that dependency during the test — so the test can deterministically
  force specific scenarios ("what if the device is unreachable?") that
  would otherwise be difficult or impossible to reliably reproduce on
  demand. Python's `pytest`, via a built-in feature called `monkeypatch`,
  lets a test temporarily replace a real function with a fake one for the
  duration of that one test only, automatically restoring the original
  afterward — you'll see `monkeypatch.setattr(...)` throughout PERDEDOR's
  test files, doing exactly this.

**Test-Driven Development (TDD)** is a specific *workflow*, not just "have
tests": write a test for a new piece of behavior *first* (it will fail,
since the behavior doesn't exist yet — this is deliberately checked, to
make sure the test is actually testing something real and isn't itself
broken), then write the minimum code needed to make that test pass, then
improve/clean up the code while continuously re-running the test to make
sure it still passes. This project's own working conventions call for
this workflow on new features.

### 18.2 Immutability, revisited

Chapter 3.8 introduced immutability as a general concept; Chapter 4.7
showed exactly how Python's `@dataclass(frozen=True)` implements it. It's
worth restating *why* this specific project leans on it so consistently:
a `Finding` object, once a check function has produced it, is never meant
to be modified by anything downstream — only read, copied-with-changes (if
truly needed, which turns out to essentially never happen in this
codebase), or included in a larger collection. Making this a *hard,
enforced rule* (an attempted mutation raises an error rather than silently
succeeding) rather than just a convention removes an entire category of
"wait, why did this finding's data change partway through the report
pipeline?" bugs before they can ever happen.

### 18.3 Graceful degradation and the "never crash the whole scan over one check" principle

A theme that comes up constantly throughout this document (and will come
up constantly again in Volume 2): almost every individual check PERDEDOR runs
is doing something that might simply not be possible on this particular
machine — a file that doesn't exist, a command that isn't installed, a
Windows-only cmdlet running on macOS, a native CPU instruction on
non-x86 hardware, a device that's currently unreachable over adb. PERDEDOR's
design treats every one of these as an entirely *expected*, individually-
handled outcome, using the `error`/`skipped` statuses (Volume 2 covers the
`Finding`/`Status` model exactly), rather than letting any single check's
failure crash or halt the entire rest of the scan. This is why you'll see
`try`/`except` (or PowerShell's `try`/`catch`) wrapped individually around
so many of PERDEDOR's checks — the failure boundary is deliberately drawn
around *each individual check*, so that one failing check can never take
down thirty working ones alongside it.

### 18.4 Weighted scoring

Not every detected sandbox tell is equally serious — a `critical`-severity
CPUID hypervisor bit leak (something essentially any piece of malware
would trivially catch, and which single-handedly gives the whole game
away) is a fundamentally bigger problem than an `info`-severity low font
count (a subtle, easily-missed signal that only the most thorough malware
would bother checking, and even then only as one weak signal among many).
A pure `clean/total` count treats these as numerically identical, which
would be actively misleading. PERDEDOR (following VMAware's own precedent,
§17.3) reports **two** numbers side by side for exactly this reason:

- **`raw_score`**: a simple `clean/applicable` count (errored/skipped
  checks excluded from the denominator, since neither is a genuine
  pass/fail result on this particular host) — an easy, VMAware-style
  headline number.
- **`weighted_score`**: a 0-100 score where each detected finding is
  discounted according to its severity, using a fixed weight table
  (`info`=0.05 through `critical`=1.0), so that a sandbox with one single
  critical leak scores meaningfully worse than one with ten low-severity
  gaps, even though the raw count alone might say otherwise. Volume 2
  shows the exact formula and code.

### 18.5 Code formatting, linting, and static analysis

- A **formatter** (PERDEDOR uses **black** for Python) automatically
  rewrites code into one single, consistent visual style (line length,
  spacing, quote style, etc.), removing any need for humans to
  argue over or manually enforce style preferences — you write
  reasonably-formed code, run the formatter, and it comes out
  byte-for-byte consistent with every other file in the project.
- An **import sorter** (PERDEDOR uses **isort**) automatically arranges a
  file's `import` statements (§4.9) into a consistent, logical order
  (standard library imports, then third-party imports, then the
  project's own internal imports, each group alphabetized).
- A **linter** (PERDEDOR uses **ruff**, a fast, modern Python linter) scans
  code for likely mistakes, bad practices, and style-guide violations
  *without* actually running it — catching things like an unused import,
  a variable that's assigned but never used, or (as came up directly
  during this project's own recent work) a `# noqa` suppression comment
  (§4.11) that's no longer doing anything, because the specific rule it
  was suppressing isn't even enabled in this project's configuration.
- **PEP 8** is Python's own official, community-standard style guide
  (naming conventions, formatting conventions, and more) — `black` and
  `ruff` together largely automate compliance with it.

### 18.6 CLI design principles

A well-designed command-line tool follows several conventions users come
to expect, mostly by long-standing Unix tradition: distinct **positional
arguments** for required, unambiguous choices (like PERDEDOR's
`perdedor test <platform>`, where the platform genuinely must be specified,
in a specific position, every time) versus optional **flags** for
everything else (§5.3); clear, actionable error messages printed to
**stderr**, not stdout (§5.6), so a script capturing the tool's real
output never accidentally captures error noise instead; and predictable,
non-zero **exit codes** (§5.5) on failure, so the tool can be reliably
used as one step inside a larger automated pipeline, with the calling
script able to detect success/failure just by checking the exit code,
without needing to parse any actual output text at all.

PERDEDOR's own CLI design goes one specific step further, deliberately: it
does *not* offer a "test everything at once, auto-detect the platform"
mode — the user must explicitly say which single platform they're testing
(`perdedor test windows`, `perdedor test linux`, or `perdedor test android`), and
only that one platform's full check suite runs. This is a direct
requirement from this project's own specification, not an accidental
limitation — the reasoning being that auto-detecting "which platform am I
even running on" is itself just another thing that could be spoofed or
get it wrong, whereas an analyst running this tool always already knows,
with complete certainty, exactly which sandbox they're testing (they just
built it), so there's no actual scenario where auto-detection would add
real value, only additional complexity and a new potential failure mode.

## Chapter 19: Networking Basics Relevant to PERDEDOR

You don't need a full networking course to understand PERDEDOR — just these
specific pieces.

### 19.1 IP addresses

An **IP address** is a numeric identifier assigned to a device on a
network, used to route data to and from it. The common form you'll see
(**IPv4**) is written as four numbers 0-255 separated by dots, e.g.
`192.168.1.1`. Certain address ranges are reserved for special purposes by
long-standing internet-wide convention:
- `127.0.0.1` ("localhost" / "loopback") always refers to "this same
  machine," regardless of what machine you're on — a way for a program to
  talk to another program on the same computer using ordinary networking
  code.
- `169.254.0.0/16` is the reserved **link-local** address range —
  addresses only meaningful and reachable *within the current, immediate
  network segment*, never routed further, and automatically self-assigned
  by devices in specific situations. Cloud providers deliberately picked
  `169.254.169.254`, a single fixed address within this reserved range,
  for their instance metadata service (§12.8), specifically *because*
  link-local addresses are inherently unreachable from outside the
  immediate host — a real security property, not just an arbitrary
  choice, ensuring the metadata service can only ever be reached by the
  instance itself, never from the broader internet.

### 19.2 MAC addresses and OUIs

Every network interface (a network card, whether physical or virtual) has
a separate, lower-level hardware identifier called a **MAC address**
("Media Access Control" address) — six bytes, conventionally written as
six pairs of hex digits (§1.3) separated by colons, e.g.
`08:00:27:3a:4c:9d`. Unlike an IP address (which can change depending on
what network you're connected to), a MAC address is meant to be a fixed,
built-in identifier for that specific piece of hardware.

The *first three bytes* of a MAC address form the **OUI** (Organizationally
Unique Identifier) — a block of addresses officially assigned by the IEEE
(a standards body) to a specific hardware manufacturer, so that (in
principle) you could look at just those first three bytes and know which
company made the device. Virtualization software needs to invent MAC
addresses for its virtual network adapters too, and — just like the
SMBIOS/DMI situation in §12.7 — most hypervisors default to using their
*own* officially-registered OUI unless an operator deliberately overrides
it: VirtualBox's default is `08:00:27` (originally registered to
"Cadmus Computer Systems," the OUI VirtualBox inherited); QEMU/KVM's
default (via libvirt) is `52:54:00`; VMware has several registered
blocks including `00:0c:29` and `00:50:56`. PERDEDOR's MAC-OUI checks
(present on both Linux and Windows) read every network interface's MAC
address and compare just its first three bytes against a table of these
known hypervisor-default OUIs.

### 19.3 HTTP and the cloud metadata check

**HTTP** (HyperText Transfer Protocol) is the standard protocol web
browsers and countless other programs use to request and receive data
over a network — a **client** sends a **request** to a specific address
(URL), and a **server** at that address sends back a **response**.
PERDEDOR's cloud-metadata-reachability check (§12.8) makes an HTTP request
to the fixed link-local metadata address, with a short **timeout**
(a maximum time to wait before giving up and treating it as failed) — and,
notably, it doesn't care *what* comes back, or whether the request even
succeeds in a conventional sense; it only cares whether *anything at all*
answered within that short window, since only a genuine cloud VM would
have anything listening there to answer at all.

## Chapter 20: Putting It All Together — How PERDEDOR's Design Falls Out of These Ideas

Before moving to Volume 2's line-by-line code walkthrough, it's worth
explicitly connecting every idea from this volume to the actual shape of
the PERDEDOR project, so the transition feels obvious rather than abrupt.

**The three-agent, one-schema architecture** (Chapter 9 + Chapter 2.4)
exists because Windows, Linux, and Android are three genuinely different
operating systems (Chapter 11), naturally programmed in different
languages best suited to each (Chapters 4, 6 — Python fits Linux/Android
cleanly; PowerShell/.NET is the natural, idiomatic choice for deep Windows
system access) — but a JSON Schema (Chapter 9) lets all three still agree
on one common *output* shape, so a human or another program consuming
PERDEDOR's results never needs to care which language or platform produced
any given report.

**The four detection categories** (Chapter 15) exist because they're a
genuinely meaningful, real technical taxonomy of *how* virtualization
leaks evidence — not an arbitrary organizational choice — and tagging
every check with one lets PERDEDOR's reports surface *where* a sandbox's
weaknesses actually cluster, rather than just a flat list.

**The native C helper** (Chapter 7) exists purely because two specific
x86 CPU instructions (Chapter 10) are fundamentally unreachable from
Python — not a performance optimization, a hard technical necessity, kept
as small and narrowly scoped as possible specifically because C's manual
memory model (Chapter 7.4) makes larger C programs meaningfully riskier to
get right.

**The P/Invoke declarations in the Windows agent** (Chapter 6.5) exist
because PowerShell/.NET, despite being much higher-level than C, still
doesn't expose *every* capability of the underlying Windows OS through its
own standard library — some things (raw firmware tables, low-level
debugger-detection APIs) are only reachable by calling directly into the
decades-old native Win32 API layer.

**Immutable data structures and graceful per-check failure handling**
(Chapter 18.2, 18.3) exist because a tool meant to run unattended, across
wildly varying, often partially-broken or partially-inapplicable
environments (a Windows-only cmdlet running on macOS during development, a
non-x86 host, an unreachable Android device) has to treat "something
didn't work" as a completely normal, first-class outcome, not an
exceptional crash — and immutability specifically prevents an entire class
of subtle bugs where one part of the code accidentally corrupts data
another part is still relying on.

**The weighted-plus-raw scoring model** (Chapter 18.4) exists because a
flat pass/fail count would flatten away exactly the information (severity)
that matters most to a human deciding what to actually go fix first.

**The explicit "out of scope" documentation** (Chapter 16.5, and Chapter
17.4's account of what none of the three prior tools do either) exists
because an honest security tool has to be just as clear about its limits
as about its coverage — a false sense of completeness is, in a real sense,
worse than no tool at all, because it breeds unwarranted confidence.

Every one of these design choices is a direct, traceable consequence of
some real technical fact covered somewhere in this volume — none of it is
arbitrary. Volume 2 now picks up exactly here, and shows you precisely
where and how each of these ideas is expressed in real, actual source
code, file by file, line by line — enough that, having read both volumes,
you could sit down with an empty folder and rebuild the entire project
yourself, understanding not just *what* each line does but *why* it has to
be that way.

## Chapter 21: Complete Glossary

Every term used anywhere in this volume, alphabetized, with a short
self-contained definition. If a fuller explanation exists elsewhere in
this document, the chapter/section is noted in parentheses.

**adb (Android Debug Bridge)** — command-line tool for controlling an
Android device/emulator from another computer, over USB or network. (11.6)

**Anti-debugging** — techniques a program uses to detect and react to
being run under a debugger. (16.4)

**ARM** — a CPU instruction-set architecture dominant in mobile devices
and modern Apple computers; distinct from x86. (10.1)

**Array** — see List.

**Assembly language** — the human-readable, lowest-level representation
of raw CPU instructions. (7.6)

**Bash** — the most common Unix/Linux command-line shell and scripting
language. (5.1)

**Big-endian** — a byte-ordering convention where the most-significant
byte comes first. Contrast Little-endian. (10.5)

**Binary (number system)** — base-2 counting, using only 0 and 1. (1.3)

**BIOS (Basic Input/Output System)** — legacy firmware that initializes
hardware before an OS boots; largely superseded by UEFI. (1.7)

**Bit** — the smallest unit of digital information, either 0 or 1. (1.2)

**Boolean** — a data type with exactly two values, true/false. (3.2)

**Boot / booting** — the process of starting a computer, from firmware
through to a running OS. (1.7)

**Branch (Git)** — an independent line of commits in a Git repository.
(8.2)

**Breakpoint** — a point in a program's execution where a debugger will
pause it. (16.3)

**Bus** — a shared communication pathway connecting hardware components,
e.g. PCI/PCIe. (1.6)

**Byte** — a group of 8 bits, able to represent 256 distinct values. (1.2)

**cgroups (control groups)** — a Linux kernel feature for limiting and
accounting resource usage per process group; one of the two pillars
containers are built on. (13.2)

**CIM (Common Information Model)** — the modern successor to WMI for
querying Windows system information. (6.7)

**Class** — a user-defined data type bundling related data (and often
behavior) together. (3.5)

**CLI (Command-Line Interface)** — a text-based way of interacting with
software, as opposed to a graphical interface. (5.1)

**cmdlet** — a PowerShell built-in command, conventionally named
`Verb-Noun`. (6.2)

**Comment** — text in source code ignored by the compiler/interpreter,
meant for human readers. (3.7)

**Commit (Git)** — a saved snapshot of a project's files at a point in
time, with a message. (8.2)

**Compiler / compiled language** — software that translates source code
into machine instructions ahead of time, before the program runs. (3.1)

**Comprehension (Python)** — compact syntax for building a new list/dict/
set from an existing one in one expression. (4.6)

**Container** — a lightweight, kernel-shared form of isolation for a
group of processes, as opposed to a full virtual machine. (13.1)

**CPU (Central Processing Unit)** — the hardware component that executes
instructions. (1.5)

**CPUID** — an x86 CPU instruction that reports information about the CPU
itself, including hypervisor presence. (10.3)

**Daemon** — a background process on Linux/Unix systems with no visible
window, providing an ongoing service. See also Service. (2.7)

**Data class / dataclass** — a restricted class style meant only to hold
data; Python's `@dataclass` decorator generates one automatically. (3.5,
4.7)

**Debugger** — a tool for running a program under close, interactive,
step-by-step supervision. (16.3)

**Decompiler** — a tool that attempts to reconstruct higher-level source
code from compiled machine code. (16.2)

**Detonation** — malware-analysis jargon for deliberately running a
suspect sample inside an isolated sandbox to observe its behavior. (14.3)

**Dictionary (dict)** — a collection of key-value pairs, looked up by
key. (3.3)

**Diff** — a comparison showing what changed between two versions of a
file. (8.2)

**Disassembler** — a tool that converts machine code back into assembly
language. (16.2)

**Distro (Linux distribution)** — an independently packaged, maintained
Linux-based OS, e.g. Ubuntu, Fedora. (11.4)

**DLL (Dynamic Link Library)** — Windows' format for shared libraries of
pre-compiled functions. (6.5)

**DMI (Desktop Management Interface)** — loosely, the same firmware
identity data as SMBIOS; often used interchangeably with that term. (1.7)

**Docker** — the most widely used container platform/toolset. (13.1)

**Dockerfile** — a text file describing how to build a Docker container
image.

**Driver** — kernel-level software specific to controlling one piece of
hardware. (2.2)

**Dunder method** — a Python "double underscore" special method, e.g.
`__init__`. (4.7)

**Endianness** — the byte-ordering convention (little vs. big) used to
lay out a multi-byte value in memory. (10.5)

**Enum (enumeration)** — a type restricted to a fixed, named set of
possible values. (4.8)

**Environment variable** — a named text value inherited by a process from
whatever started it. (2.6)

**Evasion (malware)** — techniques malware uses to detect and avoid
analysis environments. (14.5)

**Exception** — a signal raised when something goes wrong during program
execution, handled with try/except (or try/catch). (3.4)

**Executable** — a compiled, runnable program file, full of machine
instructions.

**Exit code** — the numeric result a program returns when it finishes; 0
conventionally means success. (5.5)

**f-string** — Python syntax for embedding expressions directly inside a
string literal. (4.4)

**Finding** — PERDEDOR's core data structure: the result of running exactly
one check.

**Firmware** — low-level software built into hardware, running before the
OS. (1.7)

**Flag (CLI)** — a named, usually optional command-line argument. (5.3)

**Float (floating-point number)** — a numeric data type that can hold a
fractional part. (3.2)

**Function** — a named, reusable block of code, optionally taking
parameters and returning a value. (3.4)

**Git** — the dominant distributed version control system. (8.1)

**Golden image** — a carefully hardened, reusable template VM image,
frozen and reused for future detonations. (14.6)

**GUI (Graphical User Interface)** — a visual, window/icon/menu-based way
of interacting with software, as opposed to a CLI.

**Guest** — a virtual machine running under a hypervisor. (12.1)

**Guest Additions / Guest Tools / Guest Agent** — optional companion
software installed inside a VM guest to improve the host-guest experience.
(12.6)

**Hex (hexadecimal)** — base-16 counting, using digits 0-9 and a-f. (1.3)

**Host** — the real, physical machine a hypervisor and its guests run on.
(12.1)

**HTTP (HyperText Transfer Protocol)** — the standard protocol for
web/API requests and responses. (19.3)

**Hyper-Threading** — Intel's specific implementation of simultaneous
multithreading (SMT). (10.6)

**Hypervisor** — the software layer that creates and manages virtual
machines. (12.1)

**IMDS (Instance Metadata Service)** — a cloud VM's self-description HTTP
endpoint, conventionally at 169.254.169.254. (12.8)

**Immutable / Immutability** — a value or object that cannot be changed
after creation. (3.8)

**Import** — bringing another module's/package's contents into scope for
use. (4.9)

**Index** — the numeric position of an element within an ordered
collection, starting at 0. (3.3)

**Instruction Set Architecture (ISA)** — the specific vocabulary of raw
instructions a CPU family understands, e.g. x86 or ARM. (10.1)

**Integer (int)** — a whole-number data type. (3.2)

**Interpreter / interpreted language** — software that executes source
code directly, line by line, without a separate compile step. (3.1)

**IP address** — a numeric network identifier for a device. (19.1)

**Kernel** — the core of an operating system, running with full hardware
access. (2.2)

**Kernel module** — code loadable into a running Linux kernel after boot,
often a hardware driver. (11.2)

**KVM (Kernel-based Virtual Machine)** — a Linux kernel feature turning
Linux itself into a Type-1-like hypervisor. (12.2)

**Leaf (CPUID)** — the specific "question number" placed in EAX before
executing CPUID, selecting which category of information to return.
(10.3)

**libhoudini** — a proprietary x86-to-ARM binary translation layer used
on some Android emulator images. (11.6)

**Linter** — a tool that scans source code for likely mistakes and style
violations without running it. (18.5)

**Link-local address** — an IP address range only reachable within the
immediate local network segment, e.g. 169.254.0.0/16. (19.1)

**List (array)** — an ordered, indexable sequence of values. (3.3)

**Little-endian** — a byte-ordering convention, used by x86, where the
least-significant byte comes first. (10.5)

**MAC address** — a hardware-level network interface identifier, distinct
from an IP address. (19.2)

**Machine code** — raw binary CPU instructions, the final output of
compilation.

**Makefile** — a recipe file telling the `make` build tool how to compile
a project. (7.3)

**Malware** — software deliberately designed to cause harm or gain
unauthorized access. (14.1)

**Memory (RAM)** — fast, temporary data storage that clears on power
loss. (1.4)

**Module** — a single source file's worth of related code, importable by
other code. (3.6)

**Motherboard** — a computer's main circuit board, connecting the CPU,
memory, and other components.

**Mutable** — a value or object that can be changed after creation.
Contrast Immutable. (3.8)

**Namespace (Linux kernel)** — a kernel facility giving a process group
its own isolated view of a global resource; one of the two pillars
containers are built on. (13.2)

**None / null** — a special value representing "no value at all,"
distinct from zero or an empty string. (3.2)

**OS (Operating System)** — the software layer managing hardware on
behalf of applications. (2.1)

**OUI (Organizationally Unique Identifier)** — the first three bytes of a
MAC address, identifying the manufacturer. (19.2)

**P/Invoke (Platform Invoke)** — .NET's mechanism for calling native
Win32 API functions from managed code like PowerShell/C#. (6.5)

**Package** — a collection of related modules, importable as a group.
(3.6)

**Package manager** — software for installing/removing/tracking software
packages, e.g. dpkg, rpm, pip. (11.4, 4.12)

**Paravirtualization** — a virtualization technique using guest drivers
specifically designed for fast software-to-software communication with
the hypervisor, rather than emulating real hardware. (12.5)

**Parameter / argument** — an input value a function or command accepts.
(3.4, 5.3)

**Path** — the location of a file or directory within a filesystem's tree
structure. (2.4)

**PCI / PCIe** — a standard bus for connecting internal hardware
components, each identified by a vendor/device ID. (1.6)

**Peripheral** — a hardware component connected to a computer via a bus,
e.g. a network card. (1.6)

**PEB (Process Environment Block)** — an internal, undocumented-API
Windows per-process data structure, sometimes targeted by deep anti-debug
techniques. (16.5)

**Permission** — a rule governing which users/processes may read, write,
or execute a resource. (2.5)

**PID (Process ID)** — the numeric identifier the OS assigns a running
process. (2.3)

**Pip** — Python's standard package installer. (4.12)

**Pipe** — a shell operator (`|`) connecting one command's output to
another's input. (5.3)

**Pointer** — a variable whose value is a memory address. (7.4)

**PowerShell** — Microsoft's modern, object-oriented, cross-platform
shell and scripting language. (6.1)

**Process** — a running instance of a program. (2.3)

**QEMU** — a versatile open-source machine emulator/virtualizer, usable
standalone (full software emulation) or paired with KVM (hardware
acceleration). (12.4)

**QPC (QueryPerformanceCounter)** — a Windows high-resolution timing
facility, used as an approximation where RDTSC isn't directly reachable.
(10.4)

**RAM** — see Memory.

**RDTSC (Read Time-Stamp Counter)** — an x86 CPU instruction reading a
hardware cycle counter, used for precise timing measurements. (10.4)

**Register** — a small, extremely fast CPU-internal storage slot. (1.5,
10.2)

**Regex (regular expression)** — a compact pattern-matching mini-language
for describing shapes of text. (4.10)

**Registry (Windows)** — a hierarchical database of Windows system and
application settings. (6.7)

**Remediation** — in PERDEDOR specifically, the suggested hardening fix
attached to a detected finding.

**Remote (Git)** — a copy of a Git repository hosted elsewhere, e.g. on
GitHub. (8.2)

**Repository ("repo")** — a project directory plus its full Git-tracked
history. (8.1)

**Return value** — the output value a function produces. (3.4)

**Reverse engineering** — figuring out how something works by examining
the finished product, without original source/design material. (16.1)

**Sandbox** — an isolated, disposable execution environment used to
safely run and observe untrusted/malicious software. (14.3)

**Schema (JSON Schema)** — a JSON document describing the required shape
of other JSON documents. (9.3)

**Service (Windows)** — a background process managed centrally by
Windows, with no visible window. See also Daemon. (2.7)

**Set** — an unordered collection of unique values. (3.3)

**Severity** — PERDEDOR's classification of how serious a detected finding
is: info, low, medium, high, critical.

**Shebang** — the `#!` line at the top of a script file specifying which
interpreter should run it. (5.4)

**Shell** — a program providing a text-based (or, historically, other)
interface to interact with an OS. (5.1)

**SMBIOS (System Management BIOS)** — a standardized structure of
firmware-level hardware identity data. (1.7)

**SMT (Simultaneous Multithreading)** — a CPU feature presenting each
physical core as multiple logical processors. (10.6)

**Source code** — human-readable text written in a programming language.
(3.1)

**Standard library** — the built-in functionality shipped with a
programming language, usable without installing anything extra. (4.1)

**Static analysis** — examining a program's file without running it.
Contrast Dynamic analysis. (14.2)

**stderr / stdout / stdin** — a process's standard error / output / input
communication channels. (5.6)

**String** — a text data type. (3.2)

**struct (C)** — a C data type grouping related fields together, similar
to a simple class. (7.5)

**subprocess (Python)** — the standard-library module for running
external programs and capturing their output. (4.10)

**Sysfs (`/sys`)** — a Linux virtual filesystem exposing kernel/hardware
objects. (11.1)

**systemd** — the startup and service-management system used by most
mainstream Linux distributions. (11.3)

**Terminal / console** — the visible text-entry window running a shell.
(5.1)

**Test (automated)** — code that automatically checks other code's
correctness. (18.1)

**Test-Driven Development (TDD)** — a workflow of writing a failing test
before writing the code that makes it pass. (18.1)

**TSC (Time-Stamp Counter)** — the hardware cycle counter RDTSC reads.
(10.4)

**Tuple** — an ordered, immutable sequence of values. (3.3)

**Type (data type)** — a classification of what kind of value a variable
holds and what operations make sense on it. (3.2)

**Type 1 / Type 2 hypervisor** — bare-metal vs. hosted virtualization.
(12.2)

**Type hint / type annotation** — an optional, non-enforced note in code
about a value's expected type. (4.3)

**UEFI (Unified Extensible Firmware Interface)** — the modern replacement
for legacy BIOS firmware. (1.7)

**Unit test** — a test checking one small, isolated piece of logic.
(18.1)

**Userspace** — the restricted execution mode most ordinary programs run
in, as opposed to the kernel. (2.2)

**Variable** — a named storage location holding a value that can change.
(3.2)

**Vendor ID (PCI)** — a short hex code identifying which company made a
piece of hardware, or, for virtual devices, which paravirtualization
family it belongs to. (1.6)

**Virtual environment (Python venv)** — an isolated, self-contained
Python installation and package set. (4.12)

**Virtual machine (VM)** — a complete, simulated computer running as
software, managed by a hypervisor. (12.1)

**VirtIO** — the standard paravirtualized device interface used by
QEMU/KVM and others. (12.5)

**VM exit** — the (expensive) transfer of control from a running guest
back to the hypervisor, required for certain operations. (10.4, 12.3)

**VT-x / AMD-V** — Intel's and AMD's hardware-assisted virtualization CPU
extensions. (12.3)

**Win32 API** — the low-level, decades-old native programming interface
built into Windows itself. (6.5)

**WMI (Windows Management Instrumentation)** — Windows' system for
querying structured hardware/OS information; largely superseded by CIM.
(6.7)

**Zero-based indexing** — the convention that the first element of a
collection is at index 0, not 1. (3.3)

## Chapter 22: Suggested Study Plan

You do not need to master every chapter with equal depth before moving to
Volume 2 — but this order will make Volume 2 make sense the first time
through, rather than requiring you to backtrack constantly.

**Week 1 — Absolute foundations.** Chapters 1-3 (What Is a Computer, What
Is an OS, Programming Fundamentals). Goal: be comfortable with bits/bytes/
hex, kernel-vs-userspace, processes, files, and the vocabulary of
variables/functions/control-flow/classes, even if you've never written a
line of code before.

**Week 2 — Read real code.** Chapters 4, 5, 7 (Python, Bash, C). Goal: be
able to read (not yet necessarily write from scratch) a `.py` file and a
short shell command sequence, and understand what a C pointer is and why
compiled code needs a build step. Actually install Python
(`python3 --version` to check if it's already there) and run a few tiny
scripts yourself — nothing beats typing code in and watching it run.

**Week 3 — The Windows side and tooling.** Chapters 6, 8, 9 (PowerShell/
.NET, Git, JSON). Goal: understand P/Invoke conceptually (you don't need
to write your own P/Invoke declarations from memory yet), be comfortable
with `git status`/`git add`/`git commit`/`git log`, and be able to read
and hand-write small JSON documents.

**Week 4 — Architecture and virtualization, the technical core.** Chapters
10, 11, 12 (Computer Architecture, OS Internals, Virtualization). Go
slowly here — this is the densest, most important material in the whole
volume. Goal: be able to explain, in your own words, out loud, without
looking anything up: what CPUID leaf 1 bit 31 means, why the hypervisor-
vendor leaf's register order differs from leaf 0's, what a VM exit is and
why it's slow, what VirtIO is and why its PCI vendor ID is such a strong
signal, and what SMBIOS/DMI data is and why hypervisors have to fake it.

**Week 5 — The security/malware-analysis context.** Chapters 13, 14, 15,
16, 17 (Containers, Sandboxes, Evasion Techniques, Reverse Engineering,
Prior Art). Goal: be able to place any given detection technique into one
of the four categories correctly, on your own, without checking, and
explain why Pafish/al-khaser/VMAware weren't enough on their own.

**Week 6 — Engineering practice, then synthesis.** Chapters 18, 19, 20
(Security Engineering Practices, Networking, Putting It All Together).
Goal: understand *why* PERDEDOR is built the way it is, not just *what* it
does — this chapter's synthesis should feel like it's stating things you
already independently believe, based on everything before it, rather than
introducing new information.

**Ongoing**: keep Chapter 21 (Glossary) open in a tab. You will forget
specific terms; that's expected and fine — the glossary exists exactly for
that.

**When you're ready for Volume 2:** you should be able to answer "why does
this project need three separate agents instead of one shared codebase?",
"why is there a tiny C program in a project that's otherwise pure Python
and PowerShell?", and "why does the CPU vendor-string decoding logic care
so much about register order?" — in your own words, without flipping back
through this document. If you can do that, you're ready. If not, that's a
completely normal, useful signal about exactly which chapter to revisit —
not a failure.

---

**End of Volume 1.** Continue to
[`BUILD_GUIDE_VOL2_PERDEDOR_FROM_SCRATCH.md`](BUILD_GUIDE_VOL2_PERDEDOR_FROM_SCRATCH.md)
for the complete, line-by-line walkthrough of PERDEDOR's actual source code —
everything in this volume was building toward being able to read that
document and understand *every single line* of it, well enough to
reproduce the entire project yourself from an empty folder.

