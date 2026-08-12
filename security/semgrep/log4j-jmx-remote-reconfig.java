import javax.management.MBeanServer;
import javax.management.ObjectName;

/** Fixtures for log4j-jmx-remote-reconfig. Compiles against the JDK alone (java.management). */
class JmxRemoteReconfigCases {

    // --- vulnerable ------------------------------------------------------

    /** Exactly what a real remote JMX client does -- see XIncludeJmxProof.java. */
    void pushConfigText(MBeanServer mbs, ObjectName contextAdmin, String attackerSuppliedXml) throws Exception {
        // ruleid: log4j-jmx-remote-reconfig
        mbs.invoke(
                contextAdmin,
                "setConfigText",
                new Object[] {attackerSuppliedXml, "UTF-8"},
                new String[] {"java.lang.String", "java.lang.String"});
    }

    /** The sibling operation: points the LoggerContext at an attacker-hosted URI instead. */
    void pushConfigLocation(MBeanServer mbs, ObjectName contextAdmin, String attackerSuppliedUri) throws Exception {
        // ruleid: log4j-jmx-remote-reconfig
        mbs.invoke(
                contextAdmin, "setConfigLocationUri", new Object[] {attackerSuppliedUri}, new String[] {
                    "java.lang.String"
                });
    }

    /** Re-enabling Log4j's JMX instrumentation, which defaults to disabled (JmxUtil.isJmxDisabled()). */
    void enableJmxInstrumentation() {
        // ruleid: log4j-jmx-remote-reconfig
        System.setProperty("log4j2.disable.jmx", "false");
    }

    // --- safe --------------------------------------------------------------

    /** A read-only JMX operation on the same MBean -- not a reconfiguration sink. */
    String readConfigText(MBeanServer mbs, ObjectName contextAdmin) throws Exception {
        // ok: log4j-jmx-remote-reconfig
        return (String) mbs.invoke(contextAdmin, "getConfigText", new Object[] {}, new String[] {});
    }

    /** Explicitly keeping Log4j's JMX instrumentation off -- the documented default, stated explicitly. */
    void keepJmxDisabled() {
        // ok: log4j-jmx-remote-reconfig
        System.setProperty("log4j2.disable.jmx", "true");
    }

    /** An unrelated JMX operation name on an unrelated MBean -- same invoke() shape, different target entirely. */
    void unrelatedJmxCall(MBeanServer mbs, ObjectName someOtherMBean) throws Exception {
        // ok: log4j-jmx-remote-reconfig
        mbs.invoke(someOtherMBean, "gc", new Object[] {}, new String[] {});
    }
}
