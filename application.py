import os
import requests

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, flash
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///tourism.db")



#-------------------#
#------ INDEX ------#
#-------------------#
@app.route("/")
def index():
    """Show wellcome page"""

    #user_id = session["user_id"]
    if session.get("user_id") is None:
        user_id = 0
    else:
        user_id = session["user_id"]

    return render_template("index.html")



#----------------------#
#------ THE CITY ------#
#----------------------#
@app.route("/theCity")
def theCity():
    """Show the page of the city"""

    #user_id = session["user_id"]
    if session.get("user_id") is None:
        id_user = 0
    else:
        id_user = session["user_id"]

    return render_template("theCity.html")



#-----------------------------#
#------ TURISTIC PLACES ------#
#-----------------------------#
@app.route("/turisticPlaces", methods=["GET", "POST"])
def turisticPlaces():
    """Show the page of turistic places"""

    rowsTP = db.execute("SELECT * FROM touristicPlaces")

    #user_id = session["user_id"]
    if session.get("user_id") is None:
        user_id = 0
        rowsF=[]
    else:
        user_id = session["user_id"]
        rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)

    for r in rowsTP:
        r["fav"] = 0

        for f in rowsF:
            if r["id"] == f["p_id"] and r["type"] == f["type"]:
                r["fav"] = 1

    if request.method == "GET":
        return render_template("/turisticPlaces.html", rowsTP=rowsTP)

    if request.method == "POST":
        # Check Account
        if user_id == 0:
            flash('login to your account')
            return redirect("/login")

        temp_id = request.form.get("favTP")

        rowsTemp = db.execute("SELECT * FROM touristicPlaces WHERE id = :temp_id", temp_id=temp_id)

        if len(rowsF) < 1:
            print("ENTRO")
            db.execute("INSERT INTO favorites (user_id, type, name, address, phone, p_id) VALUES (:user_id, :type_p, :name, :address, :phone, :p_id)", user_id=user_id, type_p=rowsTemp[0]["type"], name=rowsTemp[0]["name"], address=rowsTemp[0]["address"], phone=0, p_id=rowsTemp[0]["id"])
            rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)

            #return render_template("/turisticPlaces.html", rowsTP=rowsTP)
            #return ('', 204)
            return redirect("/turisticPlaces")

        else:
            x=0
            for r in rowsF:
                if r["p_id"] == rowsTemp[0]["id"] and r["type"] == rowsTemp[0]["type"]:
                    x=1

            if x==0:
                db.execute("INSERT INTO favorites (user_id, type, name, address, phone, p_id) VALUES (:user_id, :type_p, :name, :address, :phone, :p_id)", user_id=user_id, type_p=rowsTemp[0]["type"], name=rowsTemp[0]["name"], address=rowsTemp[0]["address"], phone=0, p_id=rowsTemp[0]["id"])
                rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)
            else:
                print("EXISTE")

            #return render_template("/turisticPlaces.html", rowsTP=rowsTP)
            #return ('', 204)
            return redirect("/turisticPlaces")



#-------------------------#
#------ RESTAURANTS ------#
#-------------------------#
@app.route("/restaurants", methods=["GET", "POST"])
def restaurants():
    """Show the page of restaurants"""

    rowsR = db.execute("SELECT * FROM restaurants")

    #user_id = session["user_id"]
    if session.get("user_id") is None:
        user_id = 0
        rowsF=[]
    else:
        user_id = session["user_id"]
        rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)

    for r in rowsR:
        r["fav"] = 0

        for f in rowsF:
            if r["id"] == f["p_id"] and r["type"] == f["type"]:
                r["fav"] = 1

    if request.method == "GET":
        return render_template("restaurants.html", rowsR=rowsR)

    if request.method == "POST":
        # Check Account
        if user_id == 0:
            flash('login to your account')
            return redirect("/login")

        temp_id = request.form.get("favR")

        rowsTemp = db.execute("SELECT * FROM restaurants WHERE id = :temp_id", temp_id=temp_id)

        if len(rowsF) < 1:
            print("ENTRO")
            db.execute("INSERT INTO favorites (user_id, type, name, address, phone, p_id) VALUES (:user_id, :type_p, :name, :address, :phone, :p_id)", user_id=user_id, type_p=rowsTemp[0]["type"], name=rowsTemp[0]["name"], address=rowsTemp[0]["address"], phone=rowsTemp[0]["phone"], p_id=rowsTemp[0]["id"])
            rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)

            #return render_template("/restaurants.html", rowsR=rowsR)
            #return ('', 204)
            return redirect("/restaurants")

        else:
            x = 0
            for r in rowsF:
                if r["p_id"] == rowsTemp[0]["id"] and r["type"] == rowsTemp[0]["type"]:
                    x = 1

            if x == 0:
                db.execute("INSERT INTO favorites (user_id, type, name, address, phone, p_id) VALUES (:user_id, :type_p, :name, :address, :phone, :p_id)", user_id=user_id, type_p=rowsTemp[0]["type"], name=rowsTemp[0]["name"], address=rowsTemp[0]["address"], phone=rowsTemp[0]["phone"], p_id=rowsTemp[0]["id"])
                rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)
            else:
                print("EXISTE")

            #return render_template("/restaurants.html", rowsR=rowsR)
            #return ('', 204)
            return redirect("/restaurants")


#--------------------#
#------ HOTELS ------#
#--------------------#
@app.route("/hotels", methods=["GET", "POST"])
def hotels():
    """Show the page of restaurants"""

    rowsH = db.execute("SELECT * FROM hotels")

    #user_id = session["user_id"]
    if session.get("user_id") is None:
        user_id = 0
        rowsF=[]
    else:
        user_id = session["user_id"]
        rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)

    for r in rowsH:
        r["fav"] = 0

        for f in rowsF:
            if r["id"] == f["p_id"] and r["type"] == f["type"]:
                r["fav"] = 1

    if request.method == "GET":
        return render_template("hotels.html", rowsH=rowsH)

    if request.method == "POST":
        # Check Account
        if user_id == 0:
            flash('login to your account')
            return redirect("/login")

        temp_id = request.form.get("favH")

        rowsTemp = db.execute("SELECT * FROM hotels WHERE id = :temp_id", temp_id=temp_id)

        if len(rowsF) < 1:
            print("ENTRO")
            db.execute("INSERT INTO favorites (user_id, type, name, address, phone, p_id) VALUES (:user_id, :type_p, :name, :address, :phone, :p_id)", user_id=user_id, type_p=rowsTemp[0]["type"], name=rowsTemp[0]["name"], address=rowsTemp[0]["address"], phone=rowsTemp[0]["phone"], p_id=rowsTemp[0]["id"])
            rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)

            #return render_template("/hotels.html", rowsH=rowsH)
            #return ('', 204)
            return redirect("/hotels")

        else:
            x = 0
            for r in rowsF:
                if r["p_id"] == rowsTemp[0]["id"] and r["type"] == rowsTemp[0]["type"]:
                    x = 1

            if x == 0:
                db.execute("INSERT INTO favorites (user_id, type, name, address, phone, p_id) VALUES (:user_id, :type_p, :name, :address, :phone, :p_id)", user_id=user_id, type_p=rowsTemp[0]["type"], name=rowsTemp[0]["name"], address=rowsTemp[0]["address"], phone=rowsTemp[0]["phone"], p_id=rowsTemp[0]["id"])
                rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id", user_id=user_id)
            else:
                print("EXISTE")

            #return render_template("/hotels.html", rowsH=rowsH)
            #return ('', 204)
            return redirect("/hotels")




#-----------------------#
#------ FAVORITES ------#
#-----------------------#
@app.route("/favorites", methods=["GET", "POST"])
@login_required
def favorites():
    """Show favorites page"""

    user_id = session["user_id"]
    rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id ORDER BY id DESC", user_id=user_id)

    if request.method == "GET":
        return render_template("favorites.html", rowsF=rowsF)

    if request.method == "POST":

        if request.form['delF']:
            print("DELETE")
            temp_id = request.form['delF']
            db.execute("DELETE FROM favorites WHERE id = :temp_id", temp_id=temp_id)
            rowsF = db.execute("SELECT * FROM favorites WHERE user_id = :user_id ORDER BY id DESC", user_id=user_id)
            return render_template("favorites.html", rowsF=rowsF)

        #return render_template("favorites.html", rowsF=rowsF)



#------------------#
#------ VIEW ------#
#------------------#
@app.route("/view", methods=["GET", "POST"])
@login_required
def view():
    """Show favorites page"""

    user_id = session["user_id"]

    if request.method == "GET":
        return render_template("view.html")

    if request.method == "POST":
        if request.form['searchF']:
            print("SEARCH")
            data = request.form['searchF']
            data = data.split(',')
            print(data)

            if data[1] == "Touristic":
                print("OPTION 1")
                rowTemp = db.execute("SELECT * FROM touristicPlaces WHERE id = :p_id", p_id=data[0])
                print(rowTemp)
                return render_template("view.html", rowTemp=rowTemp)

            if data[1] == "Restaurant":
                print("OPTION 2")
                rowTemp = db.execute("SELECT * FROM restaurants WHERE id = :p_id", p_id=data[0])
                return render_template("view.html", rowTemp=rowTemp)

            if data[1] == "Hotel":
                print("OPTION 3")
                rowTemp = db.execute("SELECT * FROM hotels WHERE id = :p_id", p_id=data[0])
                return render_template("view.html", rowTemp=rowTemp)


    return render_template("favorites.html")



#-------------------#
#------ LOGIN ------#
#-------------------#
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    if session.get("user_id"):
        session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("email"):
            flash('must provide email')
            return redirect("/login")
            #return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash('must provide password')
            return redirect("/login")
            #return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = :email", email=request.form.get("email"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash('invalid username and/or password')
            return redirect("/login")
            #return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["name"] = rows[0]["name"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")



#--------------------#
#------ LOGOUT ------#
#--------------------#
@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":

        #Check enter symbol
        if not request.form.get("symbol"):
            return apology("must enter a symbol", 403)

        symbol=request.form.get("symbol")

        url = 'https://cloud-sse.iexapis.com/stable/stock/'+ symbol +'/quote?token=pk_efb3b132699c468aa2391bd1629fbe1e'

        resp = requests.get(url)
        data = resp.json()

        #print(data["symbol"])

        return render_template("quoted.html", data=data)



#----------------------#
#------ REGISTER ------#
#----------------------#
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":

        # Check enter username
        if not request.form.get("name"):
            flash('must enter a name')
            return redirect("/register")
            #return apology("must enter a username", 403)

        # Check enter username
        if not request.form.get("email"):
            flash('must enter a email')
            return redirect("/register")
            #return apology("must enter a username", 403)

        # Check enter password
        if not request.form.get("password"):
            flash('must enter a password')
            return redirect("/register")
            #return apology("must enter a password", 403)

        # Check enter confirmation
        if not request.form.get("confirmation"):
            flash('must enter the password again')
            return redirect("/register")
            #return apology("must enter the password again", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE email = :email", email=request.form.get("email"))

        # Ensure username not exists
        if len(rows) != 0:
            flash('The email is already registered')
            return redirect("/register")
            #return apology("The username already exist", 403)

        # Check password
        password=request.form.get("password")
        confirmation=request.form.get("confirmation")

        if password != confirmation:
            flash("the password isn't the same ")
            return redirect("/register")
            #return apology("the password isn't the same ", 403)

        name=request.form.get("name")
        email=request.form.get("email")

        password_hash = generate_password_hash(password)

        db.execute("INSERT INTO users (name, email, hash) VALUES (:name, :email, :password_hash)", name=name, email=email, password_hash=password_hash)
        return redirect("/")

        return redirect("/register")



#--------------------------#
#------ NEW PASSWORD ------#
#--------------------------#
@app.route("/newPassword", methods=["GET", "POST"])
@login_required
def newPassword():
    """change password"""

    if request.method == "GET":
        return render_template("newPassword.html")

    if request.method == "POST":

        user_id = session["user_id"]

        # Check old password
        if not request.form.get("oldPassword"):
            flash('enter the old password')
            return redirect("/newPassword")
            #return apology("enter the old password", 403)

        # check new password
        if not request.form.get("newPassword"):
            flash('enter a new password')
            return redirect("/newPassword")
            #return apology("enter a new password", 403)

        # check confirmation
        elif not request.form.get("confirmation"):
            flash('enter the new password again')
            return redirect("/newPassword")
            #return apology("enter the new password again", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=user_id)

        # Ensure old password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("oldPassword")):
            flash('the old password isnt correct')
            return redirect("/newPassword")
            #return apology("the old password isnt correct", 403)

        oldPassword=request.form.get("oldPassword")
        newPassword=request.form.get("newPassword")
        confirmation=request.form.get("confirmation")

        # Check new password and old password
        if newPassword == oldPassword:
            flash('the new password is the same old password')
            return redirect("/newPassword")
            #return apology("the new password is the same old password", 403)

        # Check new password and confirmation
        if newPassword != confirmation:
            flash("the new password isn't the same ")
            return redirect("/newPassword")
            #return apology("the new password isn't the same", 403)

        new_hash = generate_password_hash(newPassword)

        db.execute("UPDATE users SET hash = :new_hash WHERE id = :user_id", new_hash=new_hash, user_id=user_id)

        # Redirect user to home page
        return redirect("/")



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
