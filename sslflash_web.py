from flask import Flask, render_template, Markup, request, redirect, url_for
from werkzeug.utils import secure_filename
import sslsnip
import os, sys, json

CURRENTDIR=os.path.abspath(os.path.dirname(__file__))
'''
CONFIG['ROOT_STORE_FILE']
CONFIG['CERT_TMPDIR']
'''
CONFIG=dict()
with open( os.path.join( CURRENTDIR, 'sslflash_web.conf') ) as fconf:
  CONFIG=json.load( fconf )


app=Flask(__name__)

def proc_sslzip(filepath, pwd):
  tct = sslsnip.TrustChainTrucker(filepath, pwd, os.path.join(CURRENTDIR, CONFIG['ROOT_STORE_FILE']))
  tct.load_certs()
  tct.make_certrees()

  pd={}
  pd['summary_num']=len(tct.certrees)
  pd['summary_leaf']=[ tree[0]['CN'] for tree in tct.certrees]

  pd['certrees']=[]
  for ct in tct.certrees:
  #ct = tct.certrees[0]
    for c in ct:
      c['INFO'] = tct.info(c['X509'])
      c['PEM'] = tct.dump_pem(c['X509'])
      if sslsnip.is_selfsigned(c['X509']):
        c['SelfSigned']=True
      else:
        c['SelfSigned']=False
      if tct.is_trusted(ct):
        c['Trusted']=True
      else:
        c['Trusted']=False

    pd['certrees'].append(ct)

  return render_template('sslflash.html', title='hoge', pd=pd)

@app.route('/',methods=['GET'])
@app.route('/index.html')
def index():
  return render_template('sslflash_form.html', pd={})


@app.route('/', methods=['POST'])
def recv_sslzip():
  try:
    if 'zipfile' not in request.files:
      raise Exception('Select a file (No file was selected)')
    if request.files['zipfile'] is None:
      raise Exception('Select a file (No filename was sent)')
    f = request.files['zipfile']
    filename = secure_filename(f.filename)
    if filename == '':
      raise Exception('Select a file (No filename was sent)')
    f.save(os.path.join(CONFIG['CERT_TMPDIR'], filename))
  
    pwd = request.form.get('pwd')
    if pwd == '':
      pwd=None
    return proc_sslzip(os.path.join(CONFIG['CERT_TMPDIR'], filename), pwd)
  except Exception as err:
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    return render_template('sslflash_form.html', pd={'message':'{} --- {} {} {}'.format(err, exc_type, fname, exc_tb.tb_lineno).encode('cp437').decode('cp932')})

@app.route('/test/')
def test():
  #tct = sslsnip.TrustChainTrucker(u'bjn.zip', u'fujitsu!2016')
  return proc_sslzip(u'bjn.zip', u'fujitsu!2016')



if __name__ == "__main__":
  app.run(debug = True)

