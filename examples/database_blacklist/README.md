# Blacklist with a database
A database is a common choice for storing blacklisted tokens. It has many
benefits over an in memory store, like redis. The most obvious benefit of
using a database is data consistency. If you add something to the database,
you don't need to worry about it vanishing in an event like a power outage.
This is huge if you need to revoke long lived keys (for example, keys that
you give to another developer so they can access your API). Another advantage
of using a database is that you have easy access to all of the relational
data stored in there. You can easily and efficiently get a list of all tokens
that belong to a given user, and revoke or unrevoke those tokens with ease.
This is very handy if you want to provide a user with a way to see all the
active tokens they have with your service.

Databases also have some cons compared to an in memory store, namely that
they are potentially slower, and they may grow huge over time and need to be
manually pruned back down.

This project contains example code for you to implement a blacklist
using a database, with some more complex features that might benefit your
application. For ease of use, we will use flask-sqlalchemy with an in
memory data store, but in production I would highly recommend using postgres.
Please note that this code is only an example, and although I do my best to
ensure its quality, it has not been thoroughly tested.
