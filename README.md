Edited version of makesig.py for Ghidra.

* Adds 24 and 32 byte options if you want to forcefully use a longer signature, these will still be unique in the binary.
  * They will not generate if nosoops original algorithm produces a longer one.
* Additional desc for output, showing what is used for what.
