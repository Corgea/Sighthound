def load_firms(cursor, firm_id, firm_name):
    cursor.execute(
        "SELECT * FROM firms WHERE firm_id = %s",
        [firm_id],
    )
    cursor.execute(
        "SELECT * FROM firms WHERE name = %(name)s",
        {"name": firm_name},
    )
    cursor.execute(
        "SELECT * FROM firms WHERE name LIKE %s",
        [f"%{firm_name}%"],
    )
