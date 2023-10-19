from tkinter import *

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from tkinter import filedialog,messagebox
from cryptography.fernet import Fernet
from hashlib import md5
import numpy as np
import sqlite3
import base64


def encryption(password):
    """Universal encryption methods for version 1.3 returns the encrypted universal key

    Args:
        password (string): password to ecrypt
    """
    def encryptMain(word):
        """Encrypts a word with matrix multiplication

        Args:
            word (string): word to encrypt

        Returns:
            string: encryoted result
        """
        options = list("1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;zxcvbnm,./QWERTYUIOP{|}ASDFGHJKL:ZXCVBNM<>?`~")
        res = ""
        while len(res) < len(word):
            C = _obtainC(word,len(options))
            for i in C:
                res +=options[i] 

        return str(res)
    def _obtainC (word, n):
        """Returns the encrypted result of a word's character
        Args:
            word (String): letter to encrypt
        Return:
            string: encrypted letter

        """
        P = _obtainP(word)
        K = _obtainK(P)
        C = np.array(np.matmul(K,P))
        for i in range (len(C)):
            C[i]= (C[i]% n)

        return C
    def _obtainK(P):
        """Generate the K matrix, the number of cols must be equal to n which is the number of letters in P."

        Args:
            P (string): string value of P

        Returns:
            K matrix.
        """
        n = len(P)
        K = [] #store the matrix
        temp = [] # row of matrix
        switch= False

        counter = 2
        for row in range(n):
            for column in range(n):
                temp.append(int((P[row]/counter)*100))

                if switch:
                    counter -= 1.5
                else:
                    counter += 1.5
            K.append(temp)
            temp = []
            switch = not switch

        return np.array(K)
    def _obtainP(word):
        """Convert a word into ASCII value

        Args:
            word (string): Word to convert

        Returns:
            list: Converted values.
        """
        word = [word]
        P = [ord(ele) for sub in word for ele in sub]
        return P
    return md5(bytes(encryptMain(password), 'utf-8')).hexdigest()


def process(passInput,loc_1,loc_2,flag):
    """Method to call the other methods, if something fails it will raise a flag

    Args:
        passInput (string): password input value
        loc_1 (string): location of the first DB
        loc_2 (string): location of the second DB
        flag (string): value of 0,1 or  None to indicate if the transfer is from 1.2 to 1.3
    """

    def startTransfer(passInput,loc_1,loc_2,flag):
        #Extract the values from the tkinter variables
        VerFlag  = flag.get()
        password = passInput.get()
        loc_2 = loc_2.get()
        loc_1 = loc_1.get()
        #Check if the user didn't obmit any inputs
        if password == "" or loc_1 =="" or loc_2=="":
            messagebox.showwarning(title="Missing Input",message="Plase fillout tall the inputs")
            return False

        connection, cursor = obtain_connection(loc_2)
        if not connection:
            messagebox.showwarning(title="Missing Database",message="Database to trasfer to not found...")
            return False

        #Save password in the new database but verify if it shares the same password the user wrote
        #The passwrod can't be extracted from the DB since the DB only has an encrypted version of the password

        if verifyPassword(password,obtain_connection(loc_1)):
            cursor.execute(f"INSERT INTO 'auth' ('ID') VALUES('{encryption(password)}')")
            connection.commit()
            connection.close()

        else: return False

        key = None

        if len(VerFlag)>0 and int(VerFlag)==0:
            key = keyCreator(password)

        #start the process
        if transfer((str(loc_1),str(loc_2)),key,password):
            return True
    
    
    def transfer(data,key,pswd):
        """Obtaines the filtered info from previous method and writes it to the new database

        Args:
            data (tuple): _description_
            key (string): key to ecrypt the passwords
            pswd (string): password used to encrypt and save in new database
        """
        rows = obtData(data[0])

        con = sqlite3.connect(data[1])
        cur = con.cursor()

        if verifyPassword(pswd,cur):

            for row in rows: 
                writter(row,con,cur,key)
        else:
            messagebox.showerror(title="Wrong password",message="The password you typed is no the same as the one saved in the database.")
            con.close()
            return False
        con.close()


    def verifyPassword(password,connection):
        """Return True if the passwords are the same

        Args:
            password (string): password input from user
            connection (sql obj): sql connection object

        Returns:
            boolean: determine if passwords are the same
        """
        cursor = connection[1]
        cursor.execute("SELECT * FROM auth")
        rows = cursor.fetchall()
        connection[0].close()

        if rows[0] == encrypt(keyCreator(password),password):
            return True
        return False


    def obtain_connection(loc):
        """Return connection to database

        Args:
            loc (string): location of the database

        Returns:
            obj: if boolean then connection failed
        """
        try:
            con = sqlite3.connect(loc)
            cur = con.cursor()
            return con,cur
        except Exception as e:
            messagebox.showerror(e)
            return False


    def obtData (loc):
        """Return all the rows from a database

        Args:
            loc (string): Location of the database 

        Returns:
            List: all the collected rows in a single object
        """
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


    def encrypt(key,data):
        """Returns MD5 ecryption of the text

        Args:
            key (string): key used to encryp the text
            data (string): data to ecrypt

        Returns:
            string: text encrypted
        """
        f = Fernet(key)
        return f.encrypt(data.encode()).decode("utf-8")


    def writter(row,con,cur,key):
        """Write the collected info into the new database

        Args:
            row (tuple): data of the specific row from previous database
            con (sql obj): connection to database object
            cur (sql obj): cursor related to the sql connection
            key (string): key to encrypt the password with
        """
        if key:
            pswrd = encrypt(key,row[2])
        else:
            pswrd = row[2]
        cur.execute(f"INSERT INTO list Values('{row[0]}','{row[1]}','{pswrd}',{getID(cur)})")
        con.commit()


    def getHashVal(text):
        """Returns hash value of a string

        Args:
            text (String): text to convert to hash

        Returns:
            String: string of hash object decrypted from byte form
        """
        return md5(bytes(text, 'utf-8')).hexdigest()


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

    try:
        if startTransfer(passInput,loc_1,loc_2,flag):
            messagebox.showinfo(title="Complete",message="Process completed!")
    except Exception as e:
        messagebox.showerror(title="Universal Error",message="Error Detected:"+str(e))
    

def _geDB_Route(text, location):
    """Obtain the location of the databases

    Args:
        text (string): varaible for a differnt title
        location (StringVar): tkinter variable to store the location
    """
    location.set (filedialog.askopenfilename(initialdir="/.",
                                           title =f"Location to {text}",
                                           filetypes=(
                                                ("Database","*.db"),
                                                ("All Files", "*.*"))
                                        )
    )
    


root = Tk()


location_1 = StringVar()
location_2 = StringVar()
version_2_flag = StringVar()
Password = StringVar()

root.geometry("400x300")
root.title(" Testing ")
 
  
Label(text = "Insert Password used in the other version of the program").pack()
passInput = Entry(root,width=40,textvariable= Password).pack()


Label(text = "Search for the location of the original database").pack()

 
Button(root, height = 2,
                 width = 20, 
                 text ="Search",
                 command=lambda: _geDB_Route("transfer data from",location_1)).pack()

Label(root,textvariable =location_1).pack()

Label(text = "Search for the location of the database to transfer to").pack()

 
Button(root, height = 2,
                 width = 20, 
                 text ="Search",
                 command=lambda: _geDB_Route("transfer data to",location_2)).pack()

Label(root,textvariable =location_2).pack()

flag = Checkbutton(root,text="Im using 1.2.X",variable=version_2_flag,offvalue=False,onvalue=True).pack()

Button(root, height = 2,
                 width = 20, 
                 text ="Transfer",
                 command=lambda: process(Password,location_1,location_2,version_2_flag)).pack()

mainloop()