from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import random

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'secure_key'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Simulated AI grading function
def analyze_assignment(file_path):
    score = random.randint(50, 100)  # Simulated score
    suggestions = [
        "Improve the structure of your writing.",
        "Add more examples to support your arguments.",
        "Check for grammar and spelling mistakes.",
        "Enhance clarity by using concise sentences."
    ]
    return score, random.sample(suggestions, 2)  # Return random suggestions

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            score, feedback = analyze_assignment(file_path)
            return render_template('result.html', score=score, feedback=feedback)
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)
