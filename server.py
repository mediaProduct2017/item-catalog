#!usr/bin/env python2
# vitualenv at tensorflow
# vagrant

from flask import Flask, render_template, url_for, request, redirect, flash, jsonify, abort
from flask import session as login_session
import random, string
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import AccessTokenCredentials
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
# read the json file, convert json data to python data

engine = create_engine('postgresql:///catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/catalog/')
def categoryAll():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(5).all()
    return render_template('categories.html', categories=categories, items=items)


@app.route('/catalog/JSON')
def categoryAllJSON():
    temp_l = list()
    temp = dict()
    categories = session.query(Category).all()
    for i in categories:
        items = session.query(Item).filter_by(
            category_id=i.id).order_by(desc(Item.id)).all()
        temp['Category'] = {'name': i.name, 'id': i.id}
        temp['Items'] = [j.serialize for j in items]
        # print temp
        temp_l.append(temp.copy())
    # return jsonify(temp_l)
    return jsonify(Categories=temp_l)


@app.route('/users/new', methods=['GET', 'POST'])
def new_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username is None or password is None:
            abort(400)  # missing arguments but '' counts
        if session.query(User).filter_by(username=username).first() is not None:
            abort(400)  # existing user
        user = User(username=username)
        user.hash_password(password)
        session.add(user)
        session.commit()
        return redirect(url_for('log_in'))
    else:
        return render_template('login.html')


@app.route('/users/login', methods=['GET', 'POST'])
def log_in():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # print password
        if username is None or password is None:
            abort(400)  # missing arguments but '' counts
        the_user = session.query(User).filter_by(username=username).first()
        if the_user is not None and the_user.verify_password(password):
            login_session['username'] = the_user.username
            login_session['user_id'] = the_user.id
            flash("logged in as '%s'!" % username)
        else:
            flash("wrong user name or password!")
        return redirect(url_for('categoryAll'))
    else:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        print "The current session state is %s" % login_session['state']
        return render_template('login.html', STATE=state)


def createUser(login_session):
    newUser = User(username=login_session['username'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(username=login_session['username']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(name):
    try:
        user = session.query(User).filter_by(username=name).one()
        return user.id
    except:  # user is None
        return None


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        # convert python data to json data
        response.headers['Content-Type'] = 'application/json'
        return response
    # Once return, no execution after it
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
        # exchange access token from the code
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    # login_session['credentials'] = credentials
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    credentials = AccessTokenCredentials(login_session['credentials'], 'user-agent-value')

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    # required data are python data, not json data

    data = answer.json()
    # convert json data to python data

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['username'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    # access_token = login_session['access_token']
    access_token = login_session['credentials']
    print 'In gdisconnect, access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['credentials']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:

        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    try:
        # print login_session['credentials']
        if login_session['credentials'] is not None:
            return gdisconnect()
    except KeyError:
        if 'username' in login_session:
            del login_session['username']
            response = make_response(json.dumps('Successfully disconnected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response
        else:
            response = make_response(json.dumps('You have not logged in.'), 400)
            response.headers['Content-Type'] = 'application/json'
            return response


@app.route('/disc')
def disc():
    print login_session['credentials']
    del login_session['credentials']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/catalog/<int:category_id>/')
def category(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    # items = session.query(Item).filter_by(category_id=category_id)
    # print items[0].name
    # return render_template('categoryitems.html', category=category)
    return render_template('categoryitems.html', category=category, items=items)


@app.route('/catalog/<int:category_id>/JSON')
def categoryItemJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Category=category.name, Items=[i.serialize for i in items])
    # return jsonify(Items=[i.serialize() for i in items]) # TypeError: 'dict' object is not callable


@app.route('/catalog/<int:category_id>/<int:item_id>/')
def item(category_id, item_id):
    the_item = session.query(Item).filter_by(id=item_id).one()
    if 'username' not in login_session or the_item.user_id != login_session['user_id']:
        return render_template('publicitem.html', item=the_item)
    # print the_item.id
    # return render_template('item.html', category_id=category_id, item_id=item_id, item=the_item)
    else:
        return render_template('item.html', item=the_item)


@app.route('/catalog/<int:category_id>/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/catalog/newcategory', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect(url_for('log_in'))
    if request.method == 'POST':
        # print login_session['user_id']
        newCategory = Category(name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash("new category created!")
        return redirect(url_for('categoryAll'))
    else:
        return render_template('newcategory.html')


@app.route('/catalog/<int:category_id>/newitem', methods=['GET', 'POST'])
def newItem(category_id):
    if 'username' not in login_session:
        return redirect(url_for('log_in'))
    if request.method == 'POST':
        newItem = Item(name=request.form['name'], description=request.form[
                           'description'], category_id=category_id, user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("new item created!")
        # return redirect(url_for('item', item_id=newItem.id))
        return redirect(url_for('item', category_id=category_id, item_id=newItem.id))
    else:
        return render_template('newitem.html', category_id=category_id)

'''    
@app.route('/restaurant/<int:restaurant_id>/<int:menu_id>/edit/', methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    return "page to edit a menu item. Task 2 complete!"    
'''


@app.route('/catalog/<int:category_id>/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect(url_for('log_in'))
    editedItem = session.query(Item).filter_by(id=item_id).one()
    if editedItem.user_id != login_session['user_id']:
        return ("<script>"
                "function myFunction() {alert('You are not authorized to edit this restaurant."
                "Please create your own item in order to edit.');}"
                "</script><body onload='myFunction();'>")
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash("item edited!")
        # return redirect(url_for('item', item_id=editedItem.id))
        return redirect(url_for('item', category_id=category_id, item_id=item_id))
    else:
        # USE THE RENDER_TEMPLATE FUNCTION BELOW TO SEE THE VARIABLES YOU
        # SHOULD USE IN YOUR EDITMENUITEM TEMPLATE
        return render_template('edititem.html', category_id=category_id, item_id=item_id, item=editedItem)


@app.route('/catalog/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect(url_for('log_in'))
    deletedCat = session.query(Category).filter_by(id=category_id).one()
    if deletedCat.user_id != login_session['user_id']:
        return ("<script>"
                "function myFunction() {alert('You are not authorized to edit this restaurant."
                "Please create your own category in order to delete.');}"
                "</script><body onload='myFunction();'>")
    if request.method == 'POST':
        if deletedCat:
            session.delete(deletedCat)
            session.commit()
            flash("category deleted!")
            return redirect(url_for('categoryAll'))
    else:
        return render_template('deletecat.html', category=deletedCat)


@app.route('/catalog/<int:category_id>/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    if 'username' not in login_session:
        return redirect(url_for('log_in'))
    deletedItem = session.query(Item).filter_by(id=item_id).one()
    if deletedItem.user_id != login_session['user_id']:
        return ("<script>"
                "function myFunction() {alert('You are not authorized to edit this restaurant."
                "Please create your own item in order to delete.');}"
                "</script><body onload='myFunction();'>")
    if request.method == 'POST':
        if deletedItem:
            session.delete(deletedItem)
            session.commit()
            flash("item deleted!")
            return redirect(url_for('category', category_id=category_id))
    else:
        return render_template('deleteitem.html', item=deletedItem)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
    # app.run(host='', port=5000)
