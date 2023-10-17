from tkinter import *
from tkinter import filedialog

def _geDB_Route(text, location):
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
version_2_flag = False

root.geometry("400x300")
root.title(" Testing ")
 
  
Label(text = "Insert Password used in the other version of the program").pack()
passInput = Text(root, height=1,width=40).pack()


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

Checkbutton(root,text="Im using 1.2.X",variable=version_2_flag,offvalue=False,onvalue=True).pack()


mainloop()