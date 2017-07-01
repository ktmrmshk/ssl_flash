from flask import Flask, render_template, Markup
import sslsnip


app=Flask(__name__)

@app.route('/')
@app.route('/index.html')
def index():
  return 'about this page'

@app.route('/test/')
def test():
  tct = sslsnip.TrustChainTrucker(u'bjn.zip', u'fujitsu!2016')
  tct.load_certs()
  tct.make_certrees()

  pd={}
  pd['summary_num']=len(tct.certrees)
  pd['summary_leaf']=[ tree[0]['CN'] for tree in tct.certrees]

  pd['certree']=[]
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

    pd['certree'].append(ct)

  return render_template('sslflash.html', title='hoge', pd=pd)




if __name__ == "__main__":
  app.run(debug = True)

