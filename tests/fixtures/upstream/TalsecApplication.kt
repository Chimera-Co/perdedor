    // Listener for security threat detection events (root, debugger, emulator, tampering, etc.)
    private val threatDetected = object : ThreatListener.ThreatDetected() {
        override fun onPrivilegedAccess() {
            // Set your reaction
            println("onPrivilegedAccess")
        }

        override fun onDebug() {
            // Set your reaction
            // Triggered only in release build
            println("onDebug")
        }

        override fun onSimulator() {
            // Set your reaction
            // Triggered only in release build
            println("onSimulator")
        }
    }

    override fun onCreate() {
    override fun onActivityCreated(a: Activity) {}
    override fun onAllChecksFinished() {}
