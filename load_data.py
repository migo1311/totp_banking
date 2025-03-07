import sys
import csv
import os
from database import Base,Accounts,Customers,Users,CustomerLog,Transactions
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker
from flask_bcrypt import Bcrypt
from flask import Flask
app = Flask(__name__)
engine = create_engine('sqlite:///database.db',connect_args={'check_same_thread': False},echo=True)
Base.metadata.bind = engine
db = scoped_session(sessionmaker(bind=engine))
bcrypt = Bcrypt(app)



def accounts():
    users_data = [
        {'usern': 'C00000001', 'name': 'ramesh', 'usert': 'executive', 'passw': 'Ramesh@001'},
        {'usern': 'C00000002', 'name': 'suresh', 'usert': 'cashier', 'passw': 'Suresh@002'},
        {'usern': 'C00000003', 'name': 'mahesh', 'usert': 'teller', 'passw': 'Mahesh@003'}
    ]
    
    for user in users_data:
        passw_hash = bcrypt.generate_password_hash(user['passw']).decode('utf-8')
        db.execute(
            text("INSERT INTO users (id, name, user_type, password) VALUES (:u, :n, :t, :p)"),
            {"u": user['usern'], "n": user['name'], "t": user['usert'], "p": passw_hash}
        )
        db.commit()
        print(f"Account for {user['name']} Completed")

if __name__ == "__main__":
    accounts()