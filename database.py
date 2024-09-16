import psycopg2
import psycopg2.extras


def get_database():
    conn = psycopg2.connect(
        dbname="blogpage",
        user="postgres",
        password="159753",
        host="localhost",
        port ="5432"

    )
    cursor_db = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    return conn,cursor_db


def close_connection(cursor,conn):
    cursor.close()
    conn.close()
