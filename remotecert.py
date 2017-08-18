import sslsnip

pem=sslsnip.get_remote_pem('aws.amazon.com')
print( sslsnip.get_expiredate(pem['X509']) )
print( sslsnip.get_cname(pem['X509']))
print( sslsnip.get_sanhosts(pem['X509']) )
