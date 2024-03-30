import flask

flask_app = flask.Flask(__name__)

flask_app.run(
    debug=False,
    host='0.0.0.0',
    port=8080
)