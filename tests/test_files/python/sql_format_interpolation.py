def load_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
