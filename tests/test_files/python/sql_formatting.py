def percent_spaced(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)


def percent_unspaced(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s"%user_id)


def percent_variable(cursor, query, user_id):
    cursor.execute(query % user_id)


def fstring_interpolation(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def string_concatenation(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)


def format_interpolation(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))


def keyword_percent_spaced(cursor, user_id):
    cursor.execute(query="SELECT * FROM users WHERE id = %s" % user_id)


def keyword_fstring_interpolation(cursor, user_id):
    cursor.execute(query=f"SELECT * FROM users WHERE id = {user_id}")


def percent_spaced_sql_identifier(cursor, user_id):
    SQL_QUERY = "SELECT * FROM users WHERE id = %s"
    cursor.execute(SQL_QUERY % user_id)

