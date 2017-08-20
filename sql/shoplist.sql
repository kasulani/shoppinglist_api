/*
Created: 20 - August - 2017
Author: Emmanuel King Kasulani
Email: kasulani@gmail.com
------------------------------------------------------------------------
Syntax for creating tables
CREATE TABLE new_table_name (
	table_column_title TYPE_OF_DATA column_constraints,
	next_column_title TYPE_OF_DATA column_constraints,
	table_constraint
	table_constraint
) INHERITS existing_table_to_inherit_from;
-----------------------------------------------------------------------*/


/* Users table holds data of user accounts created in the shopping list 
   application.
*/
CREATE TABLE users(
	username varchar(50) NOT NULL,
	email varchar(250) NOT NULL,
	password varchar(250) NOT NULL,
	firstname varchar(100),
	lastname varchar(100),
	description text, 
	PRIMARY KEY(username),
	UNIQUE(email)
);


/* Lists table holds data of the shopping lists created by users who have
   accounts in the shopping list application
*/
CREATE TABLE lists(
	list_id serial NOT NULL,
	username varchar(50) NOT NULL,
	list_name varchar(100) NOT NULL,
	description text,
	PRIMARY KEY(list_id),
	FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
);


/* Items table holds data of the Items added to the shopping lists by users
   who have accounts in the shopping list application. The *status* field in
   this table indicates if the item has been bought(True) or not bought(False)
*/
CREATE TABLE items(
	item_id serial NOT NULL,
	list_id integer NOT NULL,
	item_name varchar(100),
	description text,
	status boolean,
	PRIMARY KEY(item_id),
	FOREIGN KEY(list_id) REFERENCES lists(list_id) ON DELETE CASCADE
);
