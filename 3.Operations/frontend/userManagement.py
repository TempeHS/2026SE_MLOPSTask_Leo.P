import sqlite3 as sql
import bcrypt


def getUsers(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM user_info WHERE email = ?", (email,))
    result = cur.fetchone()
    con.close()
    if result is None:
        return False
    stored_password = result[0]
    password_bytes = password.encode("utf-8")
    if isinstance(stored_password, str):
        stored_password = stored_password.encode("utf-8")

    return bcrypt.checkpw(password_bytes, stored_password)


def insertSignup(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()

    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    hashed_password_str = hashed_password.decode("utf-8")

    try:
        cur.execute(
            "INSERT INTO user_info (email, password) VALUES (?,?)",
            (email, hashed_password_str),
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False
