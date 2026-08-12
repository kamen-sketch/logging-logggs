import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

/** Fixtures for log4j-sql-injection. Compiles against the JDK alone. */
class SqlInjectionCases {

    private final Connection connection = null;

    // --- vulnerable ------------------------------------------------------

    /** The JdbcDatabaseManager shape: identifier concatenated into an INSERT. */
    public PreparedStatement insertIntoConfiguredTable(String tableName) throws SQLException {
        StringBuilder sb = new StringBuilder("insert into ").append(tableName).append(" (ts) values (?)");
        // ruleid: log4j-sql-injection
        return connection.prepareStatement(sb.toString());
    }

    /** Column names are identifiers too, and equally unbindable. */
    public PreparedStatement selectConfiguredColumn(String columnName) throws SQLException {
        String sql = "select " + columnName + " from logs";
        // ruleid: log4j-sql-injection
        return connection.prepareStatement(sql);
    }

    /** Statement.executeQuery with a built string. */
    public void queryByLevel(Statement statement, String level) throws SQLException {
        // ruleid: log4j-sql-injection
        statement.executeQuery("select * from logs where level = '" + level + "'");
    }

    /** executeUpdate is the same sink. */
    public void deleteOlderThan(Statement statement, String cutoff) throws SQLException {
        // ruleid: log4j-sql-injection
        statement.executeUpdate("delete from logs where ts < '" + cutoff + "'");
    }

    /** String.format hides the concatenation but not the injection. */
    public PreparedStatement formattedInsert(String tableName) throws SQLException {
        String sql = String.format("insert into %s (ts) values (?)", tableName);
        // ruleid: log4j-sql-injection
        return connection.prepareStatement(sql);
    }

    // --- safe ------------------------------------------------------------

    /** Values belong in bound parameters. */
    public void insertBound(String message) throws SQLException {
        PreparedStatement statement = connection.prepareStatement("insert into logs (msg) values (?)");
        // ok: log4j-sql-injection
        statement.setString(1, message);
        statement.executeUpdate();
    }

    /** Identifier validated against a strict pattern before concatenation. */
    public PreparedStatement insertIntoValidatedTable(String tableName) throws SQLException {
        if (tableName.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            // ok: log4j-sql-injection
            return connection.prepareStatement("insert into " + tableName + " (ts) values (?)");
        }
        throw new SQLException("rejected table name");
    }

    /** A fully constant statement. */
    public PreparedStatement constantStatement() throws SQLException {
        // ok: log4j-sql-injection
        return connection.prepareStatement("insert into logs (ts, msg) values (?, ?)");
    }
}
