import sslsnip
import sys

def test_basic():
  pem=sslsnip.get_remote_pem('aws.amazon.com')
  print( sslsnip.get_expiredate(pem['X509']) )
  print( sslsnip.get_cname(pem['X509']))
  print( sslsnip.get_sanhosts(pem['X509']) )

def usage():
  print('usage: python3 remotecert.py hostlist.txt')
  
if __name__ == '__main__':
  #test_basic()

  if len(sys.argv) != 2:
    usage()
    exit()

  with open(sys.argv[1]) as f:
    for line in f:
      host = line.strip()
      if host == '':
        continue
      pem=sslsnip.get_remote_pem(host)
      cn=sslsnip.get_cname(pem['X509'])
      sans=sslsnip.get_sanhosts(pem['X509'])
      expire=sslsnip.get_expiredate(pem['X509'])
      print('{}, {}, {}, {}'.format(host, cn, ' '.join(sans), expire))


