#!usr/bin/env python2
# vitualenv at tensorflow
# vagrant

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
# import psycopg2

Base = declarative_base()


class User(Base):
    __tablename__ = 'catalog_user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(1024))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    user_id = Column(Integer, ForeignKey('catalog_user.id'))
    user = relationship(User)


class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id', ondelete='CASCADE'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('catalog_user.id'))
    user = relationship(User)
    
    @property
    def serialize(self):

        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
        }


engine = create_engine('postgresql:///catalog')


Base.metadata.create_all(engine)
