"""Android check modules. Every module that defines ``CHECKS`` is discovered
automatically (perdedor_common.discovery). Check functions take ``ctx``
(RunContext; ``ctx.target`` is the adb serial) or, in older modules, the serial."""
