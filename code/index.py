from flask_bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required
from flask import Flask, render_template

app = Flask(__name__)
app.config['SECRET_KEY'] = 'abcdefg'
bootstrap = Bootstrap(app)

class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')

@app.route('/')
def index():
    return render_template('base.html'), 200

@app.route('/user/<name>')
def greet(name):
    form = NameForm()
    return render_template("index.html", name=name, form=form)

app.run(debug=True)