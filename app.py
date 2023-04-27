import sqlite3
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def show_security_rules():
    # create connection and cursor objects
    conn = sqlite3.connect('security_rules.db')
    c = conn.cursor()

    # get search query from request
    search_query = request.args.get('search', '')

    if search_query:
        # search for rows containing search query
        c.execute('SELECT * FROM security_rules WHERE '
                  'date LIKE ? OR '
                  'hostname LIKE ? OR '
                  'rule_name LIKE ? OR '
                  'disabled LIKE ? OR '
                  'action LIKE ? OR '
                  'tag LIKE ? OR '
                  'from_list LIKE ? OR '
                  'source_list LIKE ? OR '
                  'source_user_list LIKE ? OR '
                  'to_list LIKE ? OR '
                  'destination_list LIKE ? OR '
                  'service_list LIKE ? OR '
                  'application_list LIKE ? OR '
                  'hip_profiles LIKE ? OR '
                  'category LIKE ? OR '
                  'description LIKE ? OR '
                  'log_profile LIKE ?',
                  ('%' + search_query + '%',) * 17)
        data = c.fetchall()
    else:
        # select all data from the security_rules table
        c.execute('SELECT * FROM security_rules')
        data = c.fetchall()

    # close connection
    conn.close()

    # render HTML template with data and search form
    return render_template('security_rules.html', data=data, search_query=search_query)

if __name__ == '__main__':
    app.run(debug=True)
