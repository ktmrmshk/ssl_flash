import sslsnip

pem=sslsnip.get_remote_pem('space.ktmrmshk.com')
tct = sslsnip.TrustChainTrucker()
for i in tct.info(pem['X509']):
  if 'Not After' in i[0]:
    print(i)
