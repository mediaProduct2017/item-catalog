#!usr/bin/env python2
# vitualenv at tensorflow
# vagrant

from flask import Flask, render_template, url_for, request, redirect, flash, jsonify, abort
from flask import session as login_session
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

app = Flask(__name__)

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
            abort(400) # missing arguments but '' counts
        if session.query(User).filter_by(username=username).first() is not None:
            abort(400) # existing user
        user = User(username = username)
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
            login_session['username'] = username
            flash("logged in as '%s'!" % username)
        else:
            flash("wrong user name or password!")
        return redirect(url_for('categoryAll'))
    else:
        return render_template('login.html')


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


@app.route('/catalog/<int:category_id>/<int:item_id>')
def item(category_id, item_id):
    the_item = session.query(Item).filter_by(id=item_id).one()
    # print the_item.id
    # return render_template('item.html', category_id=category_id, item_id=item_id, item=the_item)
    return render_template('item.html', item=the_item)


@app.route('/catalog/<int:category_id>/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/catalog/newcategory', methods=['GET', 'POST'])
def newCategory():

    if request.method == 'POST':
        newCategory = Category(name=request.form['name'])
        session.add(newCategory)
        session.commit()
        flash("new category created!")
        return redirect(url_for('categoryAll'))
    else:
        return render_template('newcategory.html')


@app.route('/catalog/<int:category_id>/newitem', methods=['GET', 'POST'])
def newItem(category_id):

    if request.method == 'POST':
        newItem = Item(name=request.form['name'], description=request.form[
                           'description'], category_id=category_id)
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
    editedItem = session.query(Item).filter_by(id=item_id).one()
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

@app.route('/catalog/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    deletedCat = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if deletedCat:
            session.delete(deletedCat)
            session.commit()
            flash("category deleted!")
            return redirect(url_for('categoryAll'))
    else:
        return render_template('deletecat.html', category=deletedCat)


@app.route('/catalog/<int:category_id>/<int:item_id>/delete/', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    deletedItem = session.query(Item).filter_by(id=item_id).one()
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
