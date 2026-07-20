def load_user(cursor, query, user_id):
    cursor.execute(query % user_id)
