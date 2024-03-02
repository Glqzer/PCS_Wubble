# jhmessage_server.py
#
# Simple REST server for the JMessage ecosystem. Used for Practical Cryptographic Systems (650.445/645)
# at Johns Hopkins University.
#
# This is not production code and is almost certainly full of serious bugs. Don't use it for anything
# important.
#
# Copyright 2024 Harrison Green and Matthew D. Green
# May be redistributed under the terms of the MIT License (https://opensource.org/license/mit/)

import sys, sqlite3, uuid
from passlib.hash import scrypt
from datetime import datetime
from flask import Flask
from flask import request
from flask import Response
from flask import jsonify
from flask import send_file
import os
from werkzeug.utils import secure_filename
from PIL import Image
import string
import secrets

# Global variables
alphabet = string.ascii_letters + string.digits # avaliable characters for creating apikeys
startupTime = 0
app = Flask(__name__)
conn = None 
attachmentsDir = "./JMESSAGE_FILES"
ONE_WEEK_IN_SECONDS = (7 * 3600 * 24)

APIkeyDict = {}

# Helper functions

def opendb(db_file):
    # Connect to the database
    #
    # Returns a connection object
    conn = None
    try:
        # TODO: This thread warning suppression is probably super bad!
        conn = sqlite3.connect(db_file, check_same_thread=False)
        #conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(e)
        
    return conn

def create_table(conn, sql_command):
    # Create a new table given a connection object and a SQL command
    try:
        c = conn.cursor()
        c.execute(sql_command)
        conn.commit()

    except sqlite3.Error as e:
        print(e)

def drop_table(conn, tableName):
    # Drop a table
    try:
        c = conn.cursor()
        c.execute("DROP TABLE IF EXISTS " + tableName + ";")
        conn.commit()

    except sqlite3.Error as e:
        print(e)

def eraseAttachments(conn, olderThan):
    try:
        c = conn.cursor()
        c.execute("SELECT filePath, creationTime FROM attachments;")
        attachmentList = c.fetchall()

        #print("Deleting attachments...")
        for row in attachmentList:
            if (row[1] < olderThan) or (olderThan == 0):
                #print("\t" + row[0])
                os.remove(row[0])

    except sqlite3.Error as e:
        print(e)

def getUserList(conn):
    # Get a list of users from the database
    try:
        c = conn.cursor()
        c.execute("SELECT username, createdTime, checkedTime FROM users;")
        userList = c.fetchall()

        # Convert to an array of dictionaries
        responseArray = []
        for row in userList:
            rowDict = {'username': row[0], 'creationTime': row[1], 'lastCheckedTime': row[2]}
            responseArray.append(rowDict)

        return responseArray
    
    except sqlite3.Error as e:
        print(e)
        return None
    
def getMessageList(conn, username):
    # Get a list of messages for user <username> from the database
    try:
        c = conn.cursor()
        sqlite_lookup_with_param = """SELECT userFrom, userTo, senderID, receiptID, payload FROM messages WHERE userTo = ?;"""
        data_tuple = (username, )
        c.execute(sqlite_lookup_with_param, data_tuple)
        messageList = c.fetchall()

        # Convert to an array of dictionaries
        responseArray = []
        for row in messageList:
            rowDict = {'from': row[0], 'to': row[1], 'id': row[2], 'receiptID' : row[3], 'payload' : row[4]}
            responseArray.append(rowDict)

        # Delete those messages in a separate statement (very inefficient!)
        sqlite_delete_with_param = """DELETE FROM messages WHERE userTo = ?;"""
        data_tuple = (username,)
        c.execute(sqlite_delete_with_param, data_tuple)

        # Update the user's last checked time
        sqlite_insert_with_param = """UPDATE users
                          SET checkedTime=? WHERE username=?;"""

        timestamp = getUnixTime()
        data_tuple = (timestamp, username)
        c.execute(sqlite_insert_with_param, data_tuple)

        conn.commit()

        # TODO: the dictionary entries in this list labeled "0" and "1", not "username", "timestamp" as 
        # I would like. I tried using the RowFactory attribute in conn, but it didn't work.
        # Need to fix this.
        return responseArray
    
    except sqlite3.Error as e:
        print(e)
        return None

def addNewUser(conn, username, password, encPK, sigPK):
    # Add a new user to the database
    try:
        c = conn.cursor()
        sqlite_insert_with_param = """INSERT INTO users
                          (username, pwdhash, encPK, sigPK, createdTime, checkedTime) 
                          VALUES (?, ?, ?, ?, ?, ?);"""

        pwdhash = scrypt.hash(password)
        timestamp = getUnixTime()
        data_tuple = (username, pwdhash, encPK, sigPK, timestamp, 0)
        c.execute(sqlite_insert_with_param, data_tuple)

        conn.commit()
        return True
    
    except sqlite3.Error as e:
        print(e)
        return False

def saveMessageData(conn, fromUser, toUser, senderID, receiptID, payload):
    try:
        # Generate timestamp and UUID
        timestamp = getUnixTime()
        globalID = uuid.uuid4()
    
        # Insert fields into database
        c = conn.cursor()
        sqlite_insert_with_param = """INSERT INTO messages
                          (globalID, userFrom, userTo, timestamp, senderID, receiptID, payload) 
                          VALUES (?, ?, ?, ?, ?, ?, ?);"""

        try:
            data_tuple = (str(globalID), fromUser, toUser, timestamp, senderID, receiptID, payload, )
            c.execute(sqlite_insert_with_param, data_tuple)
            conn.commit()

        except sqlite3.Error as e:
            print(e)

        return True
    
    except sqlite3.Error as e:
        print(e)
        return False
    
def verifyUserPassword(conn, username, password):
        c = conn.cursor()
        c.execute("SELECT username, pwdhash FROM users WHERE username= ?", (username,))
        userList = c.fetchall()
        if scrypt.verify(password, userList[0][1]):
            return True

        else:
            print('Password invalid!')
            return False

        print(userList)


def getPubKey(conn, username):
    c = conn.cursor()
    c.execute("SELECT encPK, sigPK FROM users WHERE username= ?", (username,))
    pubKey = c.fetchall()
    data = {'encPK': pubKey[0][0], 'sigPK': pubKey[0][1]}

    return data, 200

def storePubKey(conn, username, encPK, sigPK):
     # Add a new public key to the database
    try:
        c = conn.cursor()
        sqlite_insert_with_param = """UPDATE users
                          SET encPK=?, sigPK=? WHERE username=?;"""

        data_tuple = (encPK, sigPK, username)
        c.execute(sqlite_insert_with_param, data_tuple)

        conn.commit()
        return True
    
    except sqlite3.Error as e:
        print(e)
        return False

def getUnixTime():
    # Return the current Unix timestamp as an int
    return int(datetime.now().timestamp())

def initializeDatabase(conn, reset, testMode):
    # Initialize the database and optionally delete and/or create new tables

    # If we're asked to reset the tables, drop them all
    if reset == True:
        print("Resetting the database and remaking all tables...")
        drop_table(conn, "users")
        drop_table(conn, "messages")
        eraseAttachments(conn, 0)
        drop_table(conn, "attachments")

    # Create the "users" table
    sql_create_users_table = """ CREATE TABLE IF NOT EXISTS users (
                                        username text PRIMARY KEY,
                                        pwdhash text NOT NULL,
                                        encPK text,
                                        sigPK text,
                                        createdTime integer,
                                        checkedTime integer
                                    ); """
    
    create_table(conn, sql_create_users_table)

    # Create the "messages" table
    sql_create_messages_table = """ CREATE TABLE IF NOT EXISTS messages (
                                        globalID text PRIMARY KEY,
                                        userFrom text NOT NULL,
                                        userTo text NOT NULL,
                                        timestamp integer,
                                        senderID integer,
                                        receiptID integer,
                                        payload text
                                    ); """
    create_table(conn, sql_create_messages_table)

    # Create the "attachments" table
    sql_create_attachments_table = """ CREATE TABLE IF NOT EXISTS attachments (
                                         username text NOT NULL,
                                         creationTime integer,
                                         filePath text NOT NULL                                         
                                     ); """
    create_table(conn, sql_create_attachments_table)

    # If we're in test mode, add some dummy users to the tables
    if testMode == True:
        addNewUser(conn, username="alice", password="abc", encPK="12345", sigPK="45678")
        addNewUser(conn, username="bob", password="def", encPK="12345", sigPK="45678")
        addNewUser(conn, username="charlie", password="ghi", encPK="12345", sigPK="45678")
        addNewUser(conn, username="dave", password="jkl",  encPK="12345", sigPK="45678")

# creates a user folder if it doesn't exist
def createFolder(directory):
    a = "userFiles/{path}".format(path=directory)
    try:
        if not os.path.exists(a):
            os.makedirs(a)
            print('a')

    except OSError:
        print('Error: Creating directory. '+ directory)
    
    return a

# returns an image to program
def returnImage(imgPath):
    return Image.open(imgPath)

# Generate a random filename and set up a path
def generateRandomFilename(username):
    filename = "".join(secrets.choice(alphabet) for i in range(24))
    return (attachmentsDir + "/" + username + "/", filename + ".dat")

# creates a new api key for users
def createAPIkey(username) -> string:
    if username not in APIkeyDict:
        key = "".join(secrets.choice(alphabet) for i in range(24))
        APIkeyDict[username] = key
        return key
    else:
        return APIkeyDict[username]

def checkAPIkey(username, apikey):
    try:
        actualAPIKey = APIkeyDict[username]
        if actualAPIKey == apikey:
            return True
    except KeyError:
        return False
    
    return False

# Flask command handlers

@app.route("/")
def server_uptime():
    serverUptime = getUnixTime() - startupTime
    return f"JMessage server, uptime = {serverUptime} seconds" 

@app.route("/listUsers")
def list_users():
    userList = getUserList(conn)

    if userList != None:
        return userList, 200
    else:
        return "{ }", 403
    
@app.route('/uploadKey/<username>/<apikey>', methods = ['POST'])
def reg_pubkey(username, apikey):
    #print("Registering public key for user " + username)

    # Verify the user's credentials
    if (checkAPIkey(username, apikey) == False):
        resp = jsonify(success=False)
        return resp, 401
    
    # Parse the incoming JSON data for "encPK", "sigPK"
    data = request.json 
    encPK = data['encPK']
    sigPK = data['sigPK']

    # Make sure the values aren't too long, or empty
    if (encPK != "" and sigPK != ""):
        storePubKey(conn, username, encPK, sigPK)

    # Return success
    resp = jsonify(success=True)

    return resp

@app.route("/lookupKey/<username>")
def lookUpPubKey(username):
    result = getPubKey(conn, username)

    if result == None:
        resp = jsonify(success=False) # Return success
        return resp
    
    else: 
        return result
    
@app.route("/registerUser/<username>/<password>") 
def register_user(username,password):
    if addNewUser(conn, username, password, "", "") == True:
        return Response("{}", status=200, mimetype='application/json')   
    else: 
        return Response("{}", status=409, mimetype='application/json')   

@app.route("/login/<username>/<password>")
def logIn(username, password):
    #TODO: have log in here and make it store information locally, so that it can remain logged in and you dont have to put your hash in like 50 times.
    # this should also make an apikey 

    #print("got login")
    if verifyUserPassword(conn, username, password):
        key = createAPIkey(username)

        data = { 
            "APIKey" : key, 
        } 

        if key != "":
            return data
        else:
            return Response("{}", status=401, mimetype='application/json')   
            return resp

# allows user to upload a file which saves to a user folder
@app.route("/uploadFile/<user>/<apikey>", methods=['GET', 'POST'])
def uploadFile(user, apikey):
    APIkeResault = checkAPIkey(user, apikey)
    if APIkeResault == True:
        if request.method == 'POST':
            #print(request.get_data())
            if 'filefield' not in request.files:
                return 'No file attached', 400
            f = request.files['filefield']

            # Generate a random filename and place it in ./<attachmentsDir>/<username>/<randomfilename>
            (saveFilePath, saveFilename) = generateRandomFilename(user)

            # create the folder if it doesn't exist
            os.makedirs(saveFilePath, exist_ok=True)

            # Save the file
            fileNameAndPath = saveFilePath + saveFilename
            f.save(fileNameAndPath)   

            # Insert the file into the attachments directory
            c = conn.cursor()
            sqlite_insert_with_param = """INSERT INTO attachments 
                          (username, creationTime, filePath) 
                          VALUES (?, ?, ?);"""
            timestamp = getUnixTime()
            data_tuple = (user, timestamp, os.path.abspath(fileNameAndPath))
            c.execute(sqlite_insert_with_param, data_tuple)
            conn.commit()

            # Clear out old attachments
            timestamp = getUnixTime()
            eraseAttachments(conn, timestamp - ONE_WEEK_IN_SECONDS)

            returnFilePath = "/" + user + "/" + saveFilename
            data = { 
                "path" : returnFilePath, 
            } 

            return data, 200
        
        else: 
            return jsonify("Nothing Passed"), 400
        
    else:
        return jsonify(error=APIkeResault), 401

# returns a file to the user
@app.route("/downloadFile/<username>/<filename>")
def returnFile(username, filename):

    try:
        realPath = os.path.realpath(attachmentsDir + "/" + username + "/" + filename)

        if os.path.commonprefix((realPath, os.path.realpath(attachmentsDir))) != os.path.realpath(attachmentsDir): 
            return "<p>Invalid path</P>", 401

        return send_file(realPath, mimetype='application/octet-stream'), 200

    except:
        return "<p>File does not exist</p>", 404
    
# returns all of a users files
#@app.route("/<user>/files")
#def returnUsersFiles(user):
    # looks through all files in the directory if possible
#    try:
#        path = "userFiles/{user}".format(user=user)
#        fileList = os.listdir(path)
#        if len(fileList) == 0:
#            fileList = "{ }"
#
#        return fileList
#    
#    except Exception as e:
#        return f"404 User \"{user}\" does not exist."

# temp until client is made
    
@app.route("/sendMessage/<username>/<apikey>",methods=['GET', 'POST'])
def sendMessage(username, apikey):

    if request.method == 'POST':
        # Check that the user credentials are legitimate
        if checkAPIkey(username, apikey) == True:
            # Note, we don't trust the "from" field of the uploaded JSON
            data = request.json
            allegedFrom = data.get('from')
            sendTo = data.get('to')
            messageID = data.get('id')
            receiptID = data.get('receiptID')
            payload = data.get('payload')

            # Make sure the user posting the message matches the 'from' field
            if allegedFrom != username:
                return "<p>Message from does not match username</p>", 401

            saveMessageData(conn, username, sendTo, messageID, receiptID, payload)
            resp = jsonify(success=True)
            return resp, 200

    # Invalid request
    resp = jsonify(success=False)
    return resp, 404

@app.route("/getMessages/<username>/<apikey>",methods=['GET', 'POST'])
def getMessages(username, apikey):
    # Check that the user credentials are legitimate
    if checkAPIkey(username, apikey) == True:
        messages = getMessageList(conn, username)
        if messages != None:
            return messages, 200

    # Invalid request
    resp = jsonify(success=False)
    return resp, 401

if __name__ == '__main__':  
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-r', action='store_true', help='reset and wipe the database')
    parser.add_argument('-t', action='store_true', help='test mode, fills the database with simulated data')
    parser.add_argument('-notls', action='store_true', help='disable TLS')
    parser.add_argument('-tlscert', action='store_true', help='use TLS cert: local.crt and local.key in same directory')
    parser.add_argument("port", nargs='?', type=int, default='8080', help='server port')
    parser.add_argument("dbfile", nargs='?', default='./sqldb', help='SQL lite database file, default is ./sqldb')
    parser.add_argument("attachdir", nargs='?', default='./JMESSAGE_FILES/', help='Attachments directory, default is ./JMESSAGE_FILES')
    args = parser.parse_args()

    serverPort = args.port
    dbfile = args.dbfile
    reset = args.r
    testMode = args.t
    attachmentsDir = args.attachdir

    # Open the database file. This will quit if there's an error.
    conn = opendb(dbfile)

    if conn is not None:
        initializeDatabase(conn, reset, testMode)
        
    else:
        print("Could not initialize database, exiting.")
        exit()

    # Get the current launch time
    startupTime = getUnixTime()

    # Set up TLS options
    if args.tlscert == True:
        context = ('local.crt', 'local.key')
        print("Using TLS certificate/keyfile local.crt, local,key")
    elif args.notls == True:
        context = None
        print("Disabling TLS")
    else:
        context = 'adhoc' # default: self-signed
        print("Using TLS with self-signed certificates")

    # # Launch the Flask (development) server.
    # #app = create_app(foo)
    createFolder("")
    app.run(port=serverPort, debug=False, ssl_context=context)
    