def load_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
