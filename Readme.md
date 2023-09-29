#  Guard Dispatch Scanner


This kernel driver was developed for educational purposes, aiming to demonstrate a simple yet effective way to scan for .data ptr swap hooks.
Cheaters commonly swap these pointers to trigger kernel hooks from usermode as a means to communicate between both lands.
This driver aims to scan all .data ptrs that are called through `__guard_dispatch_icall` and do a naive range check. 


## Disclaimer


- This driver is intended for education use only and should not be used for any commercial purposes.
- The driver has not gone through comprehensive testing on all Windows versions and should not be relied on as is. (Ex.: Windows 11 no longer has `MiAttachSession` in `ntoskrnl`)
- The driver has no kind of self protection and thus should not be used in a real world environment as means of game protection.


## Overview


Due to control flow graph (CFG) it is trivial to scan an executable and find .data ptr calls. All these calls follow a very simple signature. Firstly a `qword` is moved into `rax` and then `__guard_dispatch_icall` is called. 


Cheaters can also do multiple .data ptr swaps in a single chain. This would be a problem if only hardcoded and known .data ptr's were checked (as some AC's were doing in the past); but with a simple scan for dispatch icalls this is no longer a problem.


## Further Improvements


While the core logic works, there is space for lots of improvements. There's currently no checks to what the pointer is actually pointing at. While the target address could be in a valid module, it could point to certain stubs or inbetween instructions that could look legitimate at first glance.
