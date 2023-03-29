import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hashlib import md5
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import filedialog
import base64

def openFile(pswd):
    pswd = pswd.get()
    dest_path = filedialog.askopenfilename(initialdir="/.",
                                           title ="Data base to transfer to",
                                           filetypes=(
                                                ("Database","*.db"),
                                                ("All Files", "*.*"))
                                        )
    
    ori_path = filedialog.askopenfilename(initialdir="/.",
                                          title ="Data base to transfer from",
                                          filetypes=(
                                                ("Database","*.db"),
                                                ("All Files", "*.*"))
                                        )
    
    transfer((ori_path,dest_path),pswd)

def obtData (loc):
    try:
        con = sqlite3.connect(loc)
        cur = con.cursor()
        cur.execute("SELECT site,user,pass FROM list")
        rows = cur.fetchall()
        con.close()

        return rows
    except Exception as e:
        con.close()
        print(e)

def encript(key,data):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode("utf-8")

def keyCreator(pswd):
    """Creates encription and decription key based on user input

    Args:
        pswd (String): user input of the password
    """
    password = pswd.encode()  # Convert to type bytes
    salt = getHashVal(pswd)
    salt = salt.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def getHashVal(text):
    """Returns hash value of a string

    Args:
        text (String): text to convert to hash

    Returns:
        String: string of hash object decrypted from byte form
    """
    return md5(bytes(text, 'utf-8')).hexdigest()

def getID(cur):
    """Creates a new ID for the registry

    Args:
        cur (SQL cursor object): Database cursor

    Returns:
        int: registry ID
    """
    cur.execute("SELECT id FROM List ORDER BY id;")
    id=cur.fetchall()
    try:
        id=str(id)
        temp=''
        specialChars ="[](),'"
        for specialChar in specialChars:
            id=id.replace(specialChar,'')
        if id=='':
            return 1

        for i in id:
            if i !=' ':
                temp=temp+i
            if i==' ':
                temp=''
        return int(temp)+1
    except Exception as e:
        print(e)

def writter(row,key,con,cur):
    cur.execute(f"INSERT INTO list Values('{row[0]}','{row[1]}','{encript(key,row[2])}',{getID(cur)})")
    con.commit()


def transfer(data,pswd):
    rows = obtData(data[0])
    key = keyCreator(pswd)

    con = con = sqlite3.connect(data[1])
    cur = con.cursor()
    
    for row in rows: 
        writter(row,key,con,cur)
    
    con.close()
    
    


root = Tk()
root.title("Transfer tool")
master_pass = StringVar()
pass_entry = Entry(root, textvariable=master_pass).pack()
db_search_button = Button (root, text="location", command=lambda: openFile(master_pass)).pack()

root.mainloop()