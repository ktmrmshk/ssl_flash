import sslsnip

pem=sslsnip.get_remote_pem('space.ktmrmshk.com')
print( sslsnip.get_expiredate(pem['X509']) )
