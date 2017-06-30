from flask import Flask, render_template, Markup



app=Flask(__name__)

@app.route('/')
@app.route('/index.html')
def index():
  return 'about this page'

@app.route('/test/')
def test():
  return render_template('sslflash.html', title='hoge')




if __name__ == "__main__":
  app.run(debug = True)

