from koji import KojiCertGenerator

koji_gen = KojiCertGenerator("./kojicert")
koji_gen.generate_ca_cert()
koji_gen.generate_server_cert("server")
koji_gen.generate_client_cert("danilka", ["admin"])
