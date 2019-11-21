from elastalert.ruletypes import RuleType
import sqlite3
import os

class NewPassRule(RuleType):

    def __init__(self, rules, args=None):
        super(NewPassRule, self).__init__(rules, args)
        if not os.path.exists("creddb.sqlite"):
            c = sqlite3.connect("creddb.sqlite")
            c.execute('''CREATE TABLE creds
                    ([generated_id] INTEGER PRIMARY KEY,[victim] text, [user] text, [credential] text)''')
            c.close()

    # The results of get_match_str will appear in the alert text
    def get_match_str(self, match):
        return "New cred for %s:%s:  %s" % (match['victim'], match['username'], match['password'])

    def garbage_collect(self, timestamp):
        pass

    def select_cred(self, conn, victim, user):
        cur = conn.cursor()
        cur.execute("SELECT credential FROM creds WHERE victim=? AND user=?", (victim, user))
        cred = cur.fetchall()
        try:
            t = str(cred[0])
            t= t[2:-3]
            return t
        except:
            return ""
    
    def new_cred(self, conn, victim, user, credential):
        cur = conn.cursor()
        stored_cred = self.select_cred(conn, victim, user)
        if stored_cred != credential:
            cur.execute("INSERT or REPLACE INTO creds (generated_id, victim, user, credential) values ((select generated_id from creds where victim = ? and user = ?), ?, ?, ?)", (victim, user, victim, user, credential))
            conn.commit()
            print("[+] NEW CRED FOR {}:{}: {}".format(victim, user, credential))
            return True
        return False

    def add_data(self, data):
        conn = sqlite3.connect("creddb.sqlite")
        for document in data:
            victim = document['victim']
            user = document['username']
            credential = document['password']
            if self.new_cred(conn, victim, user, credential):
                self.add_match(document)



