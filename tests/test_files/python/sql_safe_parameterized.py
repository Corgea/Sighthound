# Fixture for #35: safe DB-API 2.0 calls must not trigger sql-injection rules.
import psycopg2
import sqlite3


def get_rows(cursor, firm_id):
    cursor.execute(
        "SELECT table_name, object_id FROM ccpa_objects "
        "WHERE firm_id = %s ORDER BY table_name",
        [firm_id],
    )
    return cursor.fetchall()


def get_user(cursor, username, password):
    cursor.execute(
        "SELECT * FROM users WHERE username = %s AND password = %s",
        (username, password),
    )
    return cursor.fetchone()


def named_placeholder(cursor, params):
    cursor.execute(
        "SELECT * FROM orders WHERE user_id = %(uid)s AND status = %(status)s",
        params,
    )
    return cursor.fetchall()


# sqlite3 qmark placeholders

def sqlite_safe(user_id):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


# psycopg.sql.SQL safe composition API

try:
    from psycopg import sql as psql

    def build_query(cursor, table, column, value):
        query = psql.SQL("SELECT * FROM {} WHERE {} = %s").format(
            psql.Identifier(table),
            psql.Identifier(column),
        )
        cursor.execute(query, [value])
        return cursor.fetchall()

    def build_query_inline(cursor, table, column, value):
        cursor.execute(
            psql.SQL("SELECT * FROM {} WHERE {} = %s").format(
                psql.Identifier(table),
                psql.Identifier(column),
            ),
            [value],
        )
        return cursor.fetchall()

except ImportError:
    pass


def get_user_keyword(cursor, username, password):
    cursor.execute(
        query="SELECT * FROM users WHERE username = %s AND password = %s",
        vars=(username, password),
    )
    return cursor.fetchone()


def safe_parameterized_with_fstring(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", [f"user_{uid}"])

