# -*- coding: utf-8 -*-

from OpenSSL import crypto
import logging, re, json




def readcert_from_file(filename):
  ret=[]
  with open(filename) as f:
    txt = f.read()
    ret = readcert(txt.encode('utf-8'))
  return ret

def readcert(txt):
  ret=[]
  STATE={'internal':0, 'external':1}
  DELIMITER={'start':b'-----BEGIN CERTIFICATE-----', 'end':b'-----END CERTIFICATE-----'}
  state=STATE['external']
  tmptxt=b''
  for line in txt.split(b'\n'):
    if state == STATE['internal']:
      tmptxt+=line
      tmptxt+=b'\n'
    pos=line.find(DELIMITER['start'])
    if pos != -1:
      assert state == STATE['external'], 'state error: must be "external" but not'
      state = STATE['internal']
      assert tmptxt==b'', 'tmptxt must be empty, but not'
      tmptxt+=line[pos:]
      tmptxt+=b'\n'
    if line.startswith(DELIMITER['end']):
      assert state == STATE['internal'], 'state error: must be "internal" but not {}'.format(line)
      state = STATE['external']
      ret.append(tmptxt)
      tmptxt=b''
  else:
    return ret
  return None

import ssl
def get_remote_pem(host, port=443):
  pem=ssl.get_server_certificate((host, port))
  return parse_cert(pem)

def get_expiredate(X509):
  return timefmt2( X509.get_notAfter().decode('utf-8') )

def get_cname(X509):
  return X509.get_subject().CN

def get_sanhosts(X509):
  '''return: list of hostname like ['abc.com', 'www.abc.com', '*.abc.com'] '''
  san=[]
  for i in range( X509.get_extension_count() ):
    e = X509.get_extension(i)
    try:
      if e.get_short_name().decode('utf-8') == 'subjectAltName':
        #print( e.__str__())
        #print( e.__str__().split(', '))
        for s in e.__str__().split(', '):
          san.append( s.replace('DNS:', '') )
    except Exception as e:
      pass
  return san

def parse_cert(cert_pem, origfile=None):
  '''
  return {'CN':'www.myexample.com', 'ISSUER':'Symantec G5', 'X509': 'X509 object', 'ORIGFILE': 'hoge/text.crt'}
  '''
  ret={}
  cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
  ret['CN']=cert.get_subject().CN
  if ret['CN'] is None:
    ret['CN'] = '{} {}'.format(cert.get_subject().O, cert.get_subject().OU)
  ret['SUBJECT']=cert.get_subject()
  ret['ISSUER']=cert.get_issuer()
  ret['X509']=cert
  ret['ORIGFILE']=origfile
  return ret

def parse_file(filename):
  certs=[]
  pems=readcert_from_file(filename)
  for pem in pems:
    tmp = parse_cert(pem, filename)
    certs.append(tmp)
  return certs

def is_selfsigned(cert):
  '''
  cert: X509 object
  '''
  if cert.get_subject().CN == cert.get_issuer().CN:
    store=crypto.X509Store()
    store.add_cert(cert)

    store_ctx=crypto.X509StoreContext(store, cert)
    if store_ctx.verify_certificate() is None:
      return True
  return False

def _is_trusted_chain(certs):
  '''
  certs: array of X509 Object in order like leaf -> mid1 -> mid2 -> root

  '''
  if len(certs) == 1:
    return is_selfsigned(certs[0])
  store=crypto.X509Store()
  for c in certs[1:]:
    store.add_cert(c)
  store_ctx=crypto.X509StoreContext(store, certs[0])
  try:
    ret = store_ctx.verify_certificate()
    if ret is None:
      return True
  except crypto.X509StoreContextError:
    return False
  return False

def hexcolon(hexstr):
  hexstr = hexstr[2:]
  if len(hexstr[2:]) % 2 != 0:
    hexstr = '0' + hexstr
  return ':'.join( [hexstr[i:i+2] for i in range(0, len(hexstr), 2)])
  
def timefmt(txtz):
  '''
  txtz is like '2023 10 30 23 59 59 Z'
  return: 'October 30, 2023 at 23:59:59 GMT'
  '''
  year = txtz[0:4]
  month = txtz[4:6]
  day = txtz[6:8]
  hour = txtz[8:10]
  minute = txtz[10:12]
  second = txtz[12:14]
  MON=['January', 'Februrary', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
  month_txt = MON[int(month)-1]
  return '{} {}, {} at {}:{}:{} GMT'.format(month_txt, day, year, hour, minute, second)

def timefmt2(txtz):
  'return: 2018/7/31'
  year = txtz[0:4]
  month = txtz[4:6]
  day = txtz[6:8]
  return '{}/{}/{}'.format(year, month, day)



import zipfile
def extract_files(zipfilename, pwd=None):
  '''
    returns array of dict with filename and content text like
    [{'filename':'file1', 'body': 'include<iostd.h>...'), ...]
  '''
  ret=[]
  try:
    with zipfile.ZipFile(zipfilename) as zf:
      for i in zf.infolist():
        filename=i.filename
        if pwd is not None:
          body=zf.read(filename, pwd.encode('utf-8'))
        else:
          body=zf.read(filename)
        #ret.append({'filename': filename.encode('cp437').decode('cp932'), 'body': body})
        ret.append({'filename': filename.encode('cp437').decode('cp932'), 'body': body})
  except Exception as err:
    import traceback
    traceback.print_exc()
    logging.warning('unzip may require passwd')
    raise Exception(err)

  return ret

class TrustChainTrucker(object):
  def __init__(self, zipfilename='', pwd='', rootstorefile=''):
    self.zipfilename=zipfilename
    self.pwd=pwd
    self.certs=[]
    self.certrees=[]
    self.rootstore=[]
    self.rootstorefile=rootstorefile
    
    if rootstorefile != '':
      self.load_root()


  def load_root(self):
    self.rootstore=parse_file(self.rootstorefile)

  def load_certs(self):
    '''
    construct pems array
    '''
    files = extract_files(self.zipfilename, self.pwd)
    for f in files:
      print(f['filename'])
      pems = readcert(f['body'])
      for p in pems:
        self.certs.append( parse_cert(p, f['filename']) )

  def _make_certrees(self, cert, certstore):
    '''
    certstore is array of cert object
    returns [cert, parentcert, grandp cert]]
    '''
    parent = None
    for c in certstore:
      if cert['ISSUER'] == c['SUBJECT']:
        parent = c
        break
    
    if parent is not None:
      if is_selfsigned(parent['X509']):
        return [cert, parent]

      ptree = self._make_certrees(parent, certstore)
      ptree.insert(0, cert)
      return ptree
   
    else:
      #print('DEBUG: cert["ISSUER"]={}, file={}'.format(cert['ISSUER'], cert['ORIGFILE']))
      ret = re.search(r'^(\S+\.)+\S+$', cert['ISSUER'].__str__() )
      if not ret:
        for r in self.rootstore:
          if r['SUBJECT'] == cert['ISSUER']:
            return [cert, r]


    assert parent is None, 'parent must be None, but not: parent =>{}, cert=>{}'.format( parent, cert)
    return [cert]


  def make_certrees(self):
    # devides leaf from intermediate/root cert
    leafs=[]
    midroot=[]
    for cert in self.certs:
      ret = re.search(r'^(\S+\.)+\S+$', cert['CN'] )
      if is_selfsigned(cert['X509']):
        midroot.append(cert)
      elif ret:# and not is_selfsigned(cert['X509']):
        #print(cert['CN'], '->leaf')
        leafs.append(cert)
        #print(leafs)
      else:
        #print(cert['CN'], '->mid, root')
        midroot.append(cert)
        #print(midroot)

    #print('leaf: {}'.format(leafs))
    #print('midroot: {}'.format(midroot))
    
    for leaf in leafs:
      self.certrees.append(self._make_certrees(leaf, midroot))
  
  def is_trusted(self, certs):
    return _is_trusted_chain([ c['X509'] for c in certs] )


  def info(self, x509):
    '''
     x509: X509 Object
     return [('Version', '3 (0x02'), ('Serial Number', '0x324512345')]
    '''
    ret=list()
    ver=x509.get_version()
    ret.append(('Version', '{} ({})'.format(ver+1, hex(ver))))
    ret.append( ('Serial Number', '{}'.format(hexcolon( hex(x509.get_serial_number()) )) ) )
    ret.append( ('Signature Algorithm', '{}'.format( x509.get_signature_algorithm().decode('utf-8')      )) )
    ret.append( ('ISSUER', '{}'.format(self._x509_str(x509.get_issuer()))) )
    ret.append( ('Validity --> Not Before', '{}'.format( timefmt( x509.get_notBefore().decode('utf-8')) ) ))
    ret.append( ('Validity --> Not After', '{}'.format( timefmt( x509.get_notAfter().decode('utf-8')) ) ))
    ret.append( ('Subject', '{}'.format(self._x509_str(x509.get_subject())) ) )
    pkey=x509.get_pubkey()
    keytype=''
    if pkey.type() == crypto.TYPE_RSA:
      keytype = 'rsaEncryption'
    elif pkey.type() == crypto.TYPE_DSA:
      keytype = 'dsaEncryption'
    else:
      keytype = 'Unknown'

    ret.append( ('Subject Public Key Info --> Public Key Algorithm', '{}'.format(keytype)) )
    ret.append( ('Subject Public Key Info --> Public Key', '{} bit'.format( pkey.bits() )) )
    
    # extenstions
    for i in range( x509.get_extension_count() ):
      e = x509.get_extension(i)
      try:
        ret.append( ('X509 extensions --> {}'.format(e.get_short_name().decode('utf-8') ), '{}'.format(e.__str__()))  )
      except Exception as e:
        pass
    
    return ret


  def _x509_str(self, x509name):
    ret=str()
    if x509name.C:
      ret+='C={}, '.format(x509name.C)
    if x509name.ST:
      ret+='ST={}, '.format(x509name.ST)
    if x509name.L:
      ret+='L={}, '.format(x509name.L)
    if x509name.OU:
      ret+='OU={}, '.format(x509name.OU)
    if x509name.O:
      ret+='O={}, '.format(x509name.O)
    if x509name.CN:
      ret+='CN={}, '.format(x509name.CN)
    return ret

  def dump_pem(self, x509):
    return crypto.dump_certificate(crypto.FILETYPE_PEM, x509).decode('utf-8')



import sys
if __name__ == '__main__':


  tct = TrustChainTrucker('bjn.zip', u'fujitsu!2016', 'lib/root.txt')
  tct.load_certs()
  #print(tct.certs)
  tct.make_certrees()
  for i,t in enumerate(tct.certrees):
    print(i,t, tct.is_trusted(t), '\n')

  #print(tct.rootstore)
  c=parse_file('leaf.crt')
  print(tct.info(c[0]['X509']) )
  print(tct.dump_pem(c[0]['X509']))


  print(tct.rootstore)
