import numpy as np
import subprocess
import os
from shlex import split
from tabulate import tabulate

# Base commands
path = ''
if path == '':
    print 'Need the path to openssl'
env = {'LD_LIBRARY_PATH': path[:-5]}
cmd_s = path + 'openssl s_server -key %s%%s_priv.pem -cert %s%%s_cert.pem -optls' % (path, path)
cmd_c = path + 'openssl s_client -connect localhost:4433 -curves %s -optls'

curves = [('x25519', 'X25519'), ('x448', 'X448'), ('p256', 'P-256'), ('p384', 'P-384'), ('p521', 'P-521')]
certs = ['x25519', 'x448', 'p256', 'p384', 'p521']

FNULL = open(os.devnull, 'w')

transf = []
labels = []
cdata = []
sdata = []
pkey_gen_c = []
pkey_gen_s = []
ssl_derive_c = []
ssl_derive_s = []
tls_cert_c = []
for cert, curve in zip(certs, curves):
    cmd_s_tmp = split(cmd_s % (cert, cert))
    # print 'Server using cert: %s' % cert
    p_s = subprocess.Popen(cmd_s_tmp, stdout=subprocess.PIPE, stderr=FNULL, env=env)
    cmd_c_tmp = split(cmd_c % (curve[1]))
    # print cmd_s_tmp
    # print cmd_c_tmp
    # print '\tClient offer curve: %s' % curve[1]
    counts_c = []
    counts_s = []
    for i in range(100):
        p_c = subprocess.Popen(cmd_c_tmp, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=FNULL, env=env)
        o_c, e_c = p_c.communicate('Q\n')
        o_s = [p_s.stdout.readline()]
        while o_s[-1] != 'DONE\n':
            o_s += [p_s.stdout.readline()]
        try:
            r, w = map(int, [filter(lambda x: x.startswith('SSL handshake has'), o_c.splitlines())[0].split()[i] for i in [4,8]])

            pkey_gen_s.append(int(filter(lambda x: x.startswith('ssl_generate_pkey:'), o_s)[0].split()[1]))
            ssl_derive_s.append(int(filter(lambda x: x.startswith('ssl_derive:'), o_s)[0].split()[1]))
            count_s = int(filter(lambda x: x.startswith('server_cyclecount:'), o_s)[0].split()[1])

            pkey_gen_c.append(int(filter(lambda x: x.startswith('ssl_generate_pkey_group:'), o_c.splitlines())[0].split()[1]))
            ssl_derive_c.append(int(filter(lambda x: x.startswith('ssl_derive:'), o_c.splitlines())[0].split()[1]))
            tls_cert_c.append(int(filter(lambda x: x.startswith('tls_process_server_certificate:'), o_c.splitlines())[0].split()[1]))
            count_c = int(filter(lambda x: x.startswith('client_cyclecount:'), o_c.splitlines())[0].split()[1])
        except IndexError:
            p_s.terminate()
            print 'No count'
            exit(-1)
        counts_c.append(count_c)
        counts_s.append(count_s)
    key = '%s_%s' % (curve[0], cert)
    labels += [key]
    cdata.append(counts_c)
    sdata.append(counts_s)
    transf.append('%d/%d' % (w,r))
    print 'op_ssl_generate_pkey_group: %d (client)' % np.mean(pkey_gen_c)
    print 'op_ssl_derive: %d (client)' % np.mean(ssl_derive_c)
    print 'op_tls_process_server_certificate: %d (client)' % np.mean(tls_cert_c)
    print 'op_client_cyclecount: %d (client)\n' % np.mean(counts_c)

    print 'op_ssl_generate_pkey: %d (server)' % np.mean(pkey_gen_s)
    print 'op_ssl_derive: %d (server)' % np.mean(ssl_derive_s)
    print 'op_server_cyclecount: %d (server)' % np.mean(counts_s)
    print '-'*80
    pkey_gen_c = []
    ssl_derive_c = []
    tls_cert_c = []
    pkey_gen_s = []
    ssl_derive_s = []
    p_s.terminate()

cmean = map(int, [np.mean(d) for d in cdata])
smean = map(int, [np.mean(d) for d in sdata])

latex = [[c[1], m, rw] for c,m,rw in zip(curves, cmean, transf)]
latex.insert(0, ['Curve', 'Avg. Cycles', 'w/r'])
print 'Client:'
latex_c = tabulate(latex, tablefmt='latex_booktabs', headers='firstrow')
print latex_c
print ''

latex = [[c[1], m, rw] for c,m,rw in zip(curves, smean, transf)]
latex.insert(0, ['Curve', 'Avg. Cycles', 'w/r'])
print 'Server:'
latex_s = tabulate(latex, tablefmt='latex_booktabs', headers='firstrow')
print latex_s
print ''

with open('bench_op_c.tex', 'w') as f:
    f.write(latex_c)
with open('bench_op_s.tex', 'w') as f:
    f.write(latex_s)
