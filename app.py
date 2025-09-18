import os
from flask import Flask, render_template, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from dotenv import load_dotenv

# Import url_checker directly
sys_path = os.path.dirname(os.path.abspath(__file__))
utils_path = os.path.join(sys_path, 'utils')
import sys
sys.path.append(utils_path)
from url_checker_app import check_url_safety

# Load environment variables
load_dotenv()  # take environment variables from .env

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-for-testing')

# Form for URL submission
class URLForm(FlaskForm):
    url = StringField('Enter URL to check', validators=[DataRequired()])
    submit = SubmitField('Check URL')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = URLForm()
    result = None
    
    if form.validate_on_submit():
        url = form.url.data
        if not url.startswith('http'):
            url = 'http://' + url  # Add http:// if missing
        
        # Perform safety check using utility function
        result = check_url_safety(url)
    
    return render_template('index.html', form=form, result=result)

@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url']
    if not url.startswith('http'):
        url = 'http://' + url  # Add http:// if missing
    
    # Perform safety check using utility function
    result = check_url_safety(url)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)

