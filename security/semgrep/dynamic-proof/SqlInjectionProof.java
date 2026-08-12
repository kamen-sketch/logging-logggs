import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Proves log4j-sql-injection's sink is real: a spy standing in for
 * java.sql.Connection/PreparedStatement records the exact SQL text and bound
 * values that actually reach the JDBC layer. No real database is needed --
 * the vulnerability is that attacker data enters the SQL string itself,
 * which is observable without ever executing it.
 */
class SqlInjectionProof {

    static final class ConnectionSpy implements InvocationHandler {
        final List<String> preparedSql = new ArrayList<>();

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            if ("prepareStatement".equals(method.getName())) {
                String sql = (String) args[0];
                preparedSql.add(sql);
                return new StatementSpy(sql).asPreparedStatement();
            }
            return defaultValue(method.getReturnType());
        }

        Connection asConnection() {
            return (Connection) Proxy.newProxyInstance(
                    Connection.class.getClassLoader(), new Class<?>[] {Connection.class}, this);
        }
    }

    /** Records bound parameter values separately from the SQL text. */
    static final class StatementSpy implements InvocationHandler {
        final String sql;
        final List<String> boundValues = new ArrayList<>();

        StatementSpy(String sql) {
            this.sql = sql;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            if ("setString".equals(method.getName())) {
                boundValues.add((String) args[1]);
            }
            return defaultValue(method.getReturnType());
        }

        PreparedStatement asPreparedStatement() {
            return (PreparedStatement) Proxy.newProxyInstance(
                    PreparedStatement.class.getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, this);
        }
    }

    private static Object defaultValue(Class<?> type) {
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        return null;
    }

    private static int failed = 0;
    private static final String DROP_PAYLOAD = "logs; DROP TABLE users; --";

    public static void main(String[] args) throws Exception {
        System.out.println("=== SQL injection: dynamic proof ===\n");

        vulnerablePayloadEntersSqlText();
        validatedIdentifierRejectsPayload();
        boundParameterNeverEntersSqlText();

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    /** JdbcDatabaseManager's own shape: "insert into " + tableName + " (...". */
    private static void vulnerablePayloadEntersSqlText() throws SQLException {
        ConnectionSpy spy = new ConnectionSpy();
        Connection conn = spy.asConnection();

        StringBuilder sb = new StringBuilder("insert into ").append(DROP_PAYLOAD).append(" (ts) values (?)");
        conn.prepareStatement(sb.toString()); // ruleid: log4j-sql-injection -- unvalidated identifier

        String capturedSql = spy.preparedSql.get(0);
        assertTrue("the DROP TABLE payload appears verbatim inside the SQL reaching prepareStatement()",
                capturedSql.contains(DROP_PAYLOAD));
        System.out.println("  vulnerable: SQL sent to prepareStatement() was:\n              \""
                + capturedSql + "\"");
    }

    /** The only correct fix for an identifier: validate before concatenating. */
    private static Object validatedInsert(Connection conn, String tableName) throws SQLException {
        if (tableName.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            return conn.prepareStatement("insert into " + tableName + " (ts) values (?)"); // ok: log4j-sql-injection
        }
        throw new SQLException("rejected table name: " + tableName);
    }

    private static void validatedIdentifierRejectsPayload() {
        ConnectionSpy spy = new ConnectionSpy();
        try {
            validatedInsert(spy.asConnection(), DROP_PAYLOAD);
            failed++;
            System.out.println("  [FAIL] validated path should have thrown for a malicious identifier");
        } catch (SQLException expected) {
            assertTrue("validated path rejected the payload before building any SQL "
                    + "(prepareStatement was never called)", spy.preparedSql.isEmpty());
        }

        spy = new ConnectionSpy();
        try {
            validatedInsert(spy.asConnection(), "app_logs");
            assertTrue("validated path still works for a legitimate identifier",
                    spy.preparedSql.equals(List.of("insert into app_logs (ts) values (?)")));
        } catch (SQLException e) {
            failed++;
            System.out.println("  [FAIL] validated path rejected a legitimate table name: " + e);
        }
    }

    /** Values, unlike identifiers, belong in bound parameters -- never in the SQL text. */
    private static void boundParameterNeverEntersSqlText() throws SQLException {
        ConnectionSpy spy = new ConnectionSpy();
        Connection conn = spy.asConnection();
        String attackerMessage = "'; DROP TABLE logs; --";

        PreparedStatement ps = conn.prepareStatement("insert into logs (msg) values (?)");
        ps.setString(1, attackerMessage); // ok: log4j-sql-injection

        String sql = spy.preparedSql.get(0);
        assertTrue("bound value never appears inside the SQL text itself",
                !sql.contains(attackerMessage));
        System.out.println("  safe:       SQL text stayed \"" + sql + "\"; "
                + "attacker value only ever reached setString(), never the SQL string.");
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
