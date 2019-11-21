from elastalert.ruletypes import RuleType
import sqlite3

class NewPassRule(RuleType):

    def __init__(self):
        if not os.path.exists("creddb.sqlite"):
            c = create_connection("creddb.sqlite")
            c.execute('''CREATE TABLE creds
                    ([generated_id] INTEGER PRIMARY KEY,[host] text, [user] text, [credential] text)''')
            c.close()

    # The results of get_match_str will appear in the alert text
    def get_match_str(self, match):
        return "New cred for %s:%s:  %s" % (match['host'], match['username'], match['credential'])

    def garbage_collect(self, timestamp):
        pass

    def create_connection(db_file):
        """ create a database connection to a SQLite database """
        conn = None
        try:
            conn = sqlite3.connect(db_file)
            print(sqlite3.version)
        except Error as e:
            print(e)
        return conn

    def select_cred(conn, host, user):
        cur = conn.cursor()
        cur.execute("SELECT credential FROM creds WHERE host=? AND user=?", (host, user))
        cred = cur.fetchall()
        try:
            t = str(cred[0])
            t= t[2:-3]
            return t
        except:
            return ""
    
    def new_cred(conn, host, user, credential):
        cur = conn.cursor()
        stored_cred = select_cred(conn, host, user)
        if stored_cred != credential:
            cur.execute("INSERT or REPLACE INTO creds (generated_id, host, user, credential) values ((select generated_id from creds where host = ? and user = ?), ?, ?, ?)", (host, user, host, user, credential))
            conn.commit()
            print("[+] NEW CRED FOR {}:{}: {}".format(host, user, credential))
            return True
        return False

    def add_data(self, data):
        conn = create_connection("creddb.sqlite")
        for document in data:
            host = document['host']
            user = document['username']
            credential = document['credential']
            if new_cred(conn, host, user, credential):
                self.add_match(document)



