Brainfuck support for r2
========================

Plugins for brainfuck:
  - `bin.bf` - identify files containing braifuck code
  - `arch.bf` - code analysis for brainfuck
  - `debug.bf` - debugger using bfvm
  - `io.bfdbg` - brainfuck debugger
  - `bp.bf` - breakpoints support (experimental)

To debug a brainfuck program:

    r2 -D bf bfdbg:///tmp/bf

    > dc    # continue
    > x@scr # show screen buffer contents

The debugger creates virtual sections for code, data, screen and input.

TODO 
----
- add support for comments, ignore invalid instructions as nops
- enhance io and debugger plugins to generate sections and set arch opts

Hello World
===========

```
>+++++++++[<++++++++>-]<.>+++++++[<++++>-]<+.+++++++..+++.[-]
>++++++++[<++++>-] <.>+++++++++++[<++++++++>-]<-.--------.+++
.------.--------.[-]>++++++++[<++++>- ]<+.[-]++++++++++.
```

```
$ cat << EOF
>+++++++++[<++++++++>-]<.>+++++++[<++++>-]<+.+++++++..+++.[-]>++++++++[<++++>-] <.>+++++++++++[<++++++++>-]<-.--------.+++.------.--------.[-]>++++++++[<++++>- ]<+.[-]++++++++++.
EOF
```
