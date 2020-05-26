RArch transition plan
=====================

The refactoring plan to merge asm and anal plugins is the following:

* Asm and Anal plugins will be reimplemented as Arch plugins
* Asm plugins will be the parse ones
* Anal plugins will be used to extend the analysis
* RParse API must be loaded into RAsm

* Arch APIs will cover:
  - retrieve register profile
  - provide arch details information
  - encode and decode instructions (RAnalOp)
  - instruction descriptions (asm/d)
* Asm APIs will cover:
  - assemble one or many instruction using the arch plugins
  - asm plugins will be there until all of them get moved 
* Anal APIs will cover:
  - analyzing an opcode, basic block, function
  - handle the hints, xrefs, high runs RAnalSession behind
  - anal plugins must permit to hook some events to trigger
    the callbacks during the analysis loops or replace implementations

RAnalOp + RAsmOp = RArchInstruction
