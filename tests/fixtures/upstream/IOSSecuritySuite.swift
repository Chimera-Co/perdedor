  public static func amIJailbroken() -> Bool {
  public static func amIJailbrokenWithFailMessage() -> (jailbroken: Bool, failMessage: String) {
  public static func amIJailbrokenWithFailedChecks() -> (jailbroken: Bool,
  public static func amIRunInEmulator() -> Bool {
  public static func amIDebugged() -> Bool {
  public static func denyDebugger() {
  public static func amITampered(_ checks: [FileIntegrityCheck]) -> FileIntegrityCheckResult {
  public static func amIReverseEngineered() -> Bool {
  public static func amIReverseEngineeredWithFailedChecks() -> (reverseEngineered: Bool,
  public static func amIRuntimeHooked(
  public static func amIRuntimeHooked(
  public static func amIProxied(considerVPNConnectionAsProxy: Bool = false) -> Bool {
  public static func amIInLockdownMode() -> Bool {
  static func hasWatchpoint() -> Bool {
